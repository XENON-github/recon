#!/usr/bin/env bash
# Scheduled drift monitoring around `recon --baseline`.
#
#   drift_cron.sh <state_dir> <recon arguments...>
#   e.g. (cron):  0 * * * *  /opt/recon/scripts/drift_cron.sh /var/lib/recon-prod prod.example.lan -pCT
#
# State directory contents:
#   baseline.json   the accepted known-good state (created by the first run)
#   latest.json     the most recent scan
#   history/        a timestamped copy of every scan
#
# Exit status: 0 = no change, 5 = NEW open ports (the baseline is NOT updated, so the alert repeats
# until someone acknowledges it), other = recon's own exit code (e.g. 4 = scan failed).
# Acknowledge a change by running once with ACCEPT=1: the latest scan becomes the new baseline.
# Set RECON=/path/to/recon if it is not on PATH. Files are created private (umask 077).
set -u
[[ $# -ge 2 ]] || { sed -n '2,15p' "$0"; exit 2; }
state=$1; shift
RECON=${RECON:-recon}
umask 077
mkdir -p "$state/history"
base="$state/baseline.json"; latest="$state/latest.json"

if [[ ! -f $base ]]; then
  "$RECON" "$@" --json -q -o "$base"; rc=$?
  [[ $rc -eq 0 ]] && echo "drift_cron: baseline recorded in $base"
  exit $rc
fi

"$RECON" "$@" --json -q -o "$latest" --baseline "$base"; rc=$?
[[ -s $latest ]] && cp "$latest" "$state/history/$(date -u +%Y%m%dT%H%M%SZ)-$$.json"

if [[ $rc -eq 5 ]]; then
  echo "drift_cron: ALERT: new open ports since the baseline (see $latest)" >&2
  if [[ ${ACCEPT:-0} == 1 ]]; then cp "$latest" "$base"; echo "drift_cron: ACCEPT=1: baseline updated" >&2; fi
fi
exit $rc
