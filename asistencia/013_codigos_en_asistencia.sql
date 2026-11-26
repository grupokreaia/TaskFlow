-- Pieza 4b: Asistencia respeta licencias, vacaciones y descanso médico (códigos de día de la pieza 4a).
-- Se ejecuta DESPUÉS de 012. No toca TaskFlow.
--
-- Un día con código LCG / LSG / V / VA / DM:
--   * estado "Licencia con goce", "Licencia sin goce", "Vacaciones", "Vacaciones adelantadas" o "Descanso médico"
--   * horas requeridas = 0 (no se exigen horas ni marcajes ese día)
--   * no genera alertas de "marcajes incompletos"
-- Un día con código NA (inasistencia) sin marcajes queda con estado "Inasistencia".
--
-- IMPORTANTE: el cálculo original del día pasa a llamarse att_day_calc_base. La función att_day_calc
-- ahora lo llama y le aplica estos códigos. Cualquier cambio futuro al cálculo se hace en att_day_calc_base.

-- Los jefes de área también ven los códigos de su gente (para que el calendario coincida)
drop policy if exists att_codes_r on public.att_day_codes;
create policy att_codes_r on public.att_day_codes for select to authenticated
  using (user_id = auth.uid() or public.att_is_admin() or public.att_ctl_ok() or public.att_can_view(user_id));

do $$ begin
  if to_regprocedure('public.att_day_calc_base(uuid,date,timestamptz)') is null then
    alter function public.att_day_calc(uuid, date, timestamptz) rename to att_day_calc_base;
  end if;
end $$;

create or replace function public.att_day_calc(p_user uuid, p_date date, p_now timestamptz default now())
returns public.att_day
language plpgsql stable set search_path = public as $$
declare r public.att_day; v_code text; v_label text;
begin
  r := public.att_day_calc_base(p_user, p_date, p_now);
  if r.day_type = 'workday' then
    select c.code into v_code from public.att_day_codes c where c.user_id = p_user and c.work_date = p_date;
    v_label := case v_code
      when 'LSG' then 'Licencia sin goce' when 'LCG' then 'Licencia con goce'
      when 'V' then 'Vacaciones' when 'VA' then 'Vacaciones adelantadas' when 'DM' then 'Descanso médico' end;
    if v_label is not null then
      r.status := v_label; r.required_min := 0; r.flag := null;
      if r.entrada is null then r.late_min := null; end if;
    elsif v_code = 'NA' and r.entrada is null then
      r.status := 'Inasistencia';
    end if;
  end if;
  return r;
end $$;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    grant execute on function public.att_day_calc(uuid, date, timestamptz) to authenticated;
  end if;
end $$;

-- Alerta de marcajes faltantes: no avisa en días de licencia, vacaciones o descanso médico
create or replace function public.att_check_missing()
returns int
language plpgsql security definer set search_path = public as $$
declare s public.att_settings; e record; d date; r public.att_day; v_today date; v_loc time; v_miss text[]; n int := 0; v_name text;
begin
  select * into s from public.att_settings where id = 1;
  v_today := (now() at time zone s.tz)::date; v_loc := (now() at time zone s.tz)::time;
  for e in select em.user_id, pr.name from public.att_employees em join public.profiles pr on pr.id = em.user_id
           where em.active and coalesce(pr.active, true) loop
    for d in select (v_today - g)::date from generate_series(0, 3) g loop
      continue when d < s.alerts_from;
      r := public.att_day_calc(e.user_id, d, now());
      continue when r.day_type <> 'workday' or r.status in ('Licencia con goce', 'Licencia sin goce', 'Vacaciones', 'Vacaciones adelantadas', 'Descanso médico');
      -- el día de hoy solo se revisa 60 min después de la hora de salida del horario
      continue when d = v_today and (r.sched_end is null or v_loc < r.sched_end + interval '60 minutes');
      v_miss := array[]::text[];
      if r.entrada is null then v_miss := v_miss || 'entrada'::text; end if;
      if r.sched_bo is not null and r.salida_refri is null then v_miss := v_miss || 'salida a refrigerio'::text; end if;
      if r.sched_bo is not null and r.ingreso_refri is null then v_miss := v_miss || 'regreso de refrigerio'::text; end if;
      if r.salida is null then v_miss := v_miss || 'salida'::text; end if;
      continue when cardinality(v_miss) = 0;
      insert into public.att_alerts (user_id, work_date, kind) values (e.user_id, d, 'missing') on conflict do nothing;
      if found then
        perform public.att_notify(e.user_id, 'Marcajes incompletos',
          'Del ' || to_char(d, 'DD/MM') || ' te falta: ' || array_to_string(v_miss, ', ') || '. Pide el cambio en Asistencia.');
        perform public.att_notify_admins('Marcajes incompletos',
          e.name || ' no completó sus marcajes del ' || to_char(d, 'DD/MM') || ' (falta: ' || array_to_string(v_miss, ', ') || ').');
        n := n + 1;
      end if;
    end loop;
  end loop;
  return n;
end $$;
revoke all on function public.att_check_missing() from public, anon, authenticated;
