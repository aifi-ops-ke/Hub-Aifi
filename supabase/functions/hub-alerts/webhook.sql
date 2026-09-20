-- Wires the hub-alerts Edge Function to two production tables via pg_net.
-- Already applied directly against the hdhyhkbcnesjqydrdedl project through
-- the Supabase Management API; kept here for reference/reproducibility.
--
-- Replace <FUNCTION_URL> and <WEBHOOK_SECRET> before re-running by hand.
-- <WEBHOOK_SECRET> must match the HUB_ALERTS_WEBHOOK_SECRET edge function secret.

create extension if not exists pg_net;

create table if not exists public.hub_alert_log (
  id bigserial primary key,
  op_id text not null,
  alert_type text not null,
  detail text,
  created_at timestamptz not null default now()
);
create index if not exists hub_alert_log_lookup_idx
  on public.hub_alert_log (op_id, alert_type, created_at desc);

create or replace function public.hub_alert_webhook() returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  perform net.http_post(
    url := '<FUNCTION_URL>', -- e.g. https://hdhyhkbcnesjqydrdedl.supabase.co/functions/v1/hub-alerts
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-hub-alerts-secret', '<WEBHOOK_SECRET>'
    ),
    body := jsonb_build_object('type', TG_OP, 'table', TG_TABLE_NAME, 'record', row_to_json(NEW))
  );
  return NEW;
end;
$$;

-- Late-login: fires on every check-in (first INSERT of the day for an
-- operator). The function itself decides whether it was actually late.
drop trigger if exists trg_hub_alert_late_login on public.wfh_sessions_v2;
create trigger trg_hub_alert_late_login
after insert on public.wfh_sessions_v2
for each row execute function public.hub_alert_webhook();

-- Tab-switch: pre-filtered here to just youtube.com and any domain NOT on
-- the work-tool allowlist, so the extremely high-volume "Switched to:
-- docs.google.com / teams.microsoft.com / ..." traffic (dozens/minute per
-- operator) never even reaches the function. Keep this allowlist in sync
-- with ALLOWED_DOMAIN_SUFFIXES in index.ts — the function re-checks it
-- independently as a safety net, but this is what controls invocation volume.
drop trigger if exists trg_hub_alert_tab_switch on public.wfh_logs_v2;
create trigger trg_hub_alert_tab_switch
after insert on public.wfh_logs_v2
for each row when (
  NEW.log_type = 'tab_switch' and (
    NEW.notes ~* 'youtube'
    or (
      NEW.notes ~* '^Switched to:\s*\S'
      and not (
        substring(NEW.notes from '^Switched to:\s*([^\s(]*)')
        ~* '(^|\.)(google\.com|gstatic\.com|live\.com|microsoft\.com|microsoft|microsoftonline\.com|sharepoint\.com|office\.com|impactoutsourcing\.co\.ke|aifi\.com|aifi-hub\.vercel\.app|aifi-ops-ke\.github\.io|atlassian\.com|atlassian\.net|cursor\.com|cursor\.sh|darkreader\.org|fast\.com)$'
      )
    )
  )
)
execute function public.hub_alert_webhook();
