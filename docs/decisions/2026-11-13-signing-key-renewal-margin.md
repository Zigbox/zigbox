# Signing keys must outlive Valid-Until by 7 days

*Decided 2026-11-13, by the supervisor.*

## Decision

The weekly refresh (`.github/package-refresh.sh`) refuses a signing key whose primary or signing
subkey expires within 28 days of the signing time. The key must stay valid for 28 days: the 21 days
of `Valid-Until` plus 7 days for the owner to renew it. `Valid-Until` itself stays 21 days after the
signing time (`constants.apt_valid_seconds`).

A key that expires 21 to 28 days out is refused now, one line asking the owner to renew it. Apt would
still accept that metadata for a few more days, but a weekly run at 21 days would then leave no time
to renew before the key lapses.

## Why

The refresh runs weekly, so the window must cover a week of missed runs plus the time to act on a
refusal. With only the 21-day check, a key that expired in week four would pass the refresh
and then fail apt before the owner had any slack to renew it.

## Where the detail lives

- `.github/package-refresh.sh`: the `renew_seconds` margin and the awk window it feeds.
- `.github/package-refresh-test.sh`: the cases at 25, 45 and 75 days.
- `docs/releases/packaging.md`, "Keeping apt fresh": the rule as the runbook states it.
- `docs/decisions/2026-11-12-apt-valid-until-and-refresh.md`: the 21-day `Valid-Until` and the
  refresh design, unchanged by this decision.
