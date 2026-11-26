-- Pieza 4a: contrato de lectura del TAREO para Krea Control (solo lectura) + códigos de día manuales.
-- Se ejecuta DESPUÉS de 011. No toca TaskFlow ni cambia los cálculos de Asistencia.
--
-- Quién puede usarlo: el administrador y quien pase ctl_can_access() (administrador o área Administración de Krea Control).
-- Control NO lee tablas de Asistencia: llama solo a estas funciones.
--   att_tareo_month(mes)    -> una fila por colaborador y día: código (A, D, FE, FT, DT, NA, LSG, LCG, V, VA, DM), tardanza, extras, horas
--   att_tareo_summary(mes)  -> una fila por colaborador: conteo de días por código y totales del mes
--   att_set_day_code(...)   -> registrar un código manual (licencias, vacaciones, descanso médico, etc.) en un rango de días

-- ¿Pasa la regla de Krea Control? (si Control aún no está instalado, es falso)
create or replace function public.att_ctl_ok()
returns boolean
language plpgsql stable security definer set search_path = public as $$
declare v boolean := false;
begin
  if to_regproc('public.ctl_can_access') is null then return false; end if;
  begin
    execute 'select public.ctl_can_access()' into v;
  exception when others then
    v := false;
  end;
  return coalesce(v, false);
end $$;
revoke all on function public.att_ctl_ok() from public, anon;
grant execute on function public.att_ctl_ok() to authenticated;

-- Códigos de día puestos a mano (sobrescriben lo automático)
create table if not exists public.att_day_codes (
  user_id   uuid not null references public.profiles(id) on delete cascade,
  work_date date not null,
  code      text not null check (code in ('A', 'D', 'FE', 'FT', 'DT', 'NA', 'LSG', 'LCG', 'V', 'VA', 'DM')),
  note      text,
  set_by    uuid,
  set_at    timestamptz not null default now(),
  primary key (user_id, work_date)
);
alter table public.att_day_codes enable row level security;
drop policy if exists att_codes_r on public.att_day_codes;
create policy att_codes_r on public.att_day_codes for select to authenticated
  using (user_id = auth.uid() or public.att_is_admin() or public.att_ctl_ok());
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    grant select on public.att_day_codes to authenticated;
  end if;
end $$;

-- Registrar (o borrar con p_code = null) un código en un rango de fechas
create or replace function public.att_set_day_code(p_user uuid, p_from date, p_to date, p_code text, p_note text default null)
returns int
language plpgsql security definer set search_path = public as $$
declare n int := 0;
begin
  if not (public.att_is_admin() or public.att_ctl_ok()) then
    raise exception 'No autorizado' using errcode = '42501';
  end if;
  if not exists (select 1 from public.profiles where id = p_user) then raise exception 'Usuario no encontrado'; end if;
  if p_from is null or p_to is null or p_to < p_from then raise exception 'Rango de fechas no válido'; end if;
  if p_to - p_from > 92 then raise exception 'El rango no puede pasar de 93 días'; end if;
  if p_code is null then
    delete from public.att_day_codes where user_id = p_user and work_date between p_from and p_to;
    get diagnostics n = row_count;
  else
    if p_code not in ('A', 'D', 'FE', 'FT', 'DT', 'NA', 'LSG', 'LCG', 'V', 'VA', 'DM') then
      raise exception 'Código no válido';
    end if;
    insert into public.att_day_codes (user_id, work_date, code, note, set_by)
    select p_user, d::date, p_code, nullif(btrim(coalesce(p_note, '')), ''), auth.uid()
    from generate_series(p_from, p_to, interval '1 day') d
    on conflict (user_id, work_date) do update
      set code = excluded.code, note = excluded.note, set_by = excluded.set_by, set_at = now();
    get diagnostics n = row_count;
  end if;
  insert into public.att_audit (actor, action, detail)
  values (auth.uid(), 'código de día', jsonb_build_object('user', p_user, 'from', p_from, 'to', p_to, 'code', p_code, 'note', p_note, 'days', n));
  return n;
end $$;
revoke all on function public.att_set_day_code(uuid, date, date, text, text) from public, anon;
grant execute on function public.att_set_day_code(uuid, date, date, text, text) to authenticated;

-- Tareo del mes: una fila por colaborador y día
create or replace function public.att_tareo_month(p_month date)
returns table (
  user_id uuid, name text, work_date date,
  code text, auto_code text, manual boolean, note text,
  day_type text, status text, flag text,
  late_min int, extra_min int, worked_min int, required_min int,
  needs_review boolean
)
language plpgsql stable security definer set search_path = public as $$
declare
  s public.att_settings; m1 date; m2 date; today date; e record; d date; r public.att_day; c public.att_day_codes;
  v_auto text; v_review boolean;
begin
  if not (public.att_is_admin() or public.att_ctl_ok()) then
    raise exception 'No autorizado' using errcode = '42501';
  end if;
  select * into s from public.att_settings where id = 1;
  today := (now() at time zone coalesce(s.tz, 'America/Bogota'))::date;
  m1 := date_trunc('month', p_month)::date;
  m2 := (m1 + interval '1 month - 1 day')::date;
  for e in
    select em.user_id as uid, p.name as pname
    from public.att_employees em join public.profiles p on p.id = em.user_id
    where em.active and coalesce(p.active, true)
    order by p.name
  loop
    for d in select g::date from generate_series(m1, m2, interval '1 day') g loop
      r := public.att_day_calc(e.uid, d, now());
      select * into c from public.att_day_codes x where x.user_id = e.uid and x.work_date = d;
      v_auto := case r.day_type
        when 'holiday' then case when r.entrada is not null then 'FT' else 'FE' end
        when 'off'     then case when r.entrada is not null then 'DT' else 'D' end
        when 'workday' then case when r.entrada is not null then 'A' when d < today then 'NA' else null end
        else null end;
      v_review := c.code is null and (
        (r.day_type = 'workday' and d < today and (r.entrada is null or r.salida is null))
        or coalesce(r.flag, '') like 'Marcajes de más%');
      user_id := e.uid; name := e.pname; work_date := d;
      code := coalesce(c.code, v_auto); auto_code := v_auto; manual := c.code is not null; note := c.note;
      day_type := r.day_type; status := r.status; flag := r.flag;
      late_min := coalesce(r.late_min, 0); extra_min := coalesce(r.extra_min, 0);
      worked_min := r.worked_min; required_min := r.required_min; needs_review := v_review;
      return next;
    end loop;
  end loop;
end $$;
revoke all on function public.att_tareo_month(date) from public, anon;
grant execute on function public.att_tareo_month(date) to authenticated;

-- Resumen del mes: una fila por colaborador
create or replace function public.att_tareo_summary(p_month date)
returns table (
  user_id uuid, name text,
  dias_asistidos int, dias_descanso_feriado int, dias_trabajados_descanso int,
  lsg int, lcg int, vacaciones int, vacaciones_adelantadas int, descanso_medico int, inasistencias int, total_dias int,
  tardanza_min int, tolerancia_min int, tardanza_excedida_min int, extras_min int,
  trabajado_min int, requerido_min int, dias_por_revisar int
)
language plpgsql stable security definer set search_path = public as $$
declare tol int;
begin
  if not (public.att_is_admin() or public.att_ctl_ok()) then
    raise exception 'No autorizado' using errcode = '42501';
  end if;
  select monthly_tolerance_min into tol from public.att_settings where id = 1;
  return query
  select t.user_id, t.name,
    (count(*) filter (where t.code = 'A'))::int,
    (count(*) filter (where t.code in ('D', 'FE')))::int,
    (count(*) filter (where t.code in ('FT', 'DT')))::int,
    (count(*) filter (where t.code = 'LSG'))::int,
    (count(*) filter (where t.code = 'LCG'))::int,
    (count(*) filter (where t.code = 'V'))::int,
    (count(*) filter (where t.code = 'VA'))::int,
    (count(*) filter (where t.code = 'DM'))::int,
    (count(*) filter (where t.code = 'NA'))::int,
    count(*)::int,
    coalesce(sum(t.late_min), 0)::int, coalesce(tol, 30),
    greatest(0, coalesce(sum(t.late_min), 0) - coalesce(tol, 30))::int,
    coalesce(sum(t.extra_min), 0)::int,
    coalesce(sum(t.worked_min), 0)::int, coalesce(sum(t.required_min), 0)::int,
    (count(*) filter (where t.needs_review))::int
  from public.att_tareo_month(p_month) t
  group by t.user_id, t.name
  order by t.name;
end $$;
revoke all on function public.att_tareo_summary(date) from public, anon;
grant execute on function public.att_tareo_summary(date) to authenticated;
