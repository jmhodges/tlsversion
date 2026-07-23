#!/usr/bin/env bash
#
# Smoke test for the tlsversion analytics logging pipeline:
#
#   app (JSON on stderr) -> Cloud Logging -> tlsversion-analytics bucket
#                                                    -> Log Analytics
#
# and confirms the same lines are *excluded* from the _Default bucket.
#
# How it works: it sends HTTPS traffic to the two endpoints that emit an
# analytics line (/ and /v1/version.json), stamped with a unique User-Agent,
# then reads each hop of the pipeline back out filtered on that User-Agent so
# it never trips over real production traffic. Each stage is checked
# independently, so a failure tells you exactly which hop broke.
#
# Routing and exclusions only affect logs ingested *after* they were created,
# so this always tests with fresh traffic rather than historical lines.
#
# Requires: curl and gcloud (authenticated to the project). kubectl is
# optional; if present and pointed at the dg cluster, the pod stderr is checked
# too. Override any of the values below via the environment, e.g.
#   HOST=staging.example.com ./scripts/smoke-test-analytics.sh
set -euo pipefail

PROJECT=${PROJECT:-personal-sites-1295}
LOCATION=${LOCATION:-us-central1}
BUCKET=${BUCKET:-tlsversion-analytics}
HOST=${HOST:-www.tlsversion.com}
NAMESPACE=${NAMESPACE:-prod}
# Seconds to wait for ingestion before reading logs back. Cloud Logging is
# usually quicker than this, but sink/exclusion propagation can lag.
INGEST_WAIT=${INGEST_WAIT:-30}

# Unique per run (timestamp + PID) so the read-back matches exactly this run's
# requests and nothing else.
UA="loganalytics-smoketest-$(date +%s)-$$"

echo "==> fingerprint User-Agent: $UA"
echo

# --- 1. generate fingerprinted HTTPS traffic --------------------------------
# Only / and /v1/version.json log an analytics line, and only over TLS (the
# handler reads r.TLS). Plain HTTP just redirects and logs nothing, so every
# request here is HTTPS. The --tlsv1.2/--tlsv1.3/--http3 variants exist to
# prove tls_version and proto are actually captured, not to test curl; failures
# on the forced-version calls are tolerated so an old curl doesn't fail the run.
echo "==> 1/5 sending HTTPS traffic to $HOST (/ and /v1/version.json)"
curl -sS -A "$UA" "https://$HOST/"                -o /dev/null
curl -sS -A "$UA" "https://$HOST/v1/version.json" -o /dev/null
curl -sS -A "$UA" --tlsv1.2 --tls-max 1.2 "https://$HOST/v1/version.json" -o /dev/null || true
curl -sS -A "$UA" --tlsv1.3                "https://$HOST/v1/version.json" -o /dev/null || true
curl -sS -A "$UA" --http3                  "https://$HOST/v1/version.json" -o /dev/null 2>/dev/null || true
echo "    sent."
echo

# --- 2. pod logs (optional) -------------------------------------------------
# The analytics logger writes JSON to stdout (operator log.Printf lines go to
# stderr); `kubectl logs` shows both streams merged. `kubectl logs deploy/...`
# reads only ONE replica, so use -l app=tlsversion to read every matching pod —
# the load balancer spreads the requests above across both replicas. --prefix
# shows which pod each line is from. Seeing JSON with "message":"request" here
# proves the app half works before we blame the Cloud Logging half.
if command -v kubectl >/dev/null 2>&1; then
  echo "==> 2/5 pod logs across all replicas (grep for the fingerprint)"
  if kubectl -n "$NAMESPACE" logs -l app=tlsversion --tail=100 --prefix 2>/dev/null \
       | grep -- "$UA"; then
    echo "    found in pod logs."
  else
    echo "    (not found yet — see the troubleshooting notes at the end)"
  fi
  echo
else
  echo "==> 2/5 kubectl not found, skipping pod log check"
  echo
fi

echo "==> waiting ${INGEST_WAIT}s for log ingestion"
sleep "$INGEST_WAIT"
echo

# --- 3. Cloud Logging, project-wide -----------------------------------------
# Confirms GKE's agent parsed the line into jsonPayload.* (not textPayload) and
# that severity is INFO (the level->severity rename). If this is empty but
# step 2 found the line, the app is emitting text, not JSON.
echo "==> 3/5 Cloud Logging (project-wide) — expect >=1 row, severity INFO"
gcloud logging read \
  'resource.type="k8s_container"
   resource.labels.container_name="tlsversion"
   jsonPayload.message="request"
   jsonPayload.user_agent="'"$UA"'"' \
  --project="$PROJECT" --freshness=10m --limit=10 \
  --format='table(severity, jsonPayload.tls_version, jsonPayload.kind, jsonPayload.proto)'
echo

# --- 4. dedicated bucket ----------------------------------------------------
# Reads from the bucket itself, so a non-empty result proves the sink filter
# matched and delivery works. Empty here + non-empty in step 3 => sink problem.
echo "==> 4/5 dedicated bucket '$BUCKET' — expect >=1 row (sink routing works)"
gcloud logging read \
  'jsonPayload.message="request"
   jsonPayload.user_agent="'"$UA"'"' \
  --project="$PROJECT" --location="$LOCATION" --bucket="$BUCKET" --view=_AllLogs \
  --freshness=10m --limit=10 \
  --format='table(timestamp, jsonPayload.tls_version, jsonPayload.kind)'
echo

# --- 5. _Default exclusion --------------------------------------------------
# The same lines should NOT also be in _Default, or we're double-storing.
echo "==> 5/5 _Default bucket — expect ZERO rows (exclusion works)"
default_hits=$(gcloud logging read \
  'jsonPayload.message="request"
   jsonPayload.user_agent="'"$UA"'"' \
  --project="$PROJECT" --location=global --bucket=_Default --view=_Default \
  --freshness=10m --limit=10 --format='value(timestamp)' | grep -c . || true)
if [ "$default_hits" -eq 0 ]; then
  echo "    OK: no analytics lines in _Default."
else
  echo "    WARN: $default_hits line(s) still landing in _Default — check the"
  echo "          exclusion filter on the _Default sink."
fi
echo

# The linked BigQuery dataset's name is the bucket's link_id: the bucket name
# with dashes turned into underscores (tlsversion-analytics ->
# tlsversion_analytics).
BQ_DATASET="${BUCKET//-/_}"

cat <<EOF
==> Log Analytics — read the same rows back via the linked BigQuery dataset.
    json_payload columns are JSON-typed, so both SELECT and WHERE need
    JSON_VALUE(), and \`proto\` is a reserved word so its alias is backticked.
    This command works verbatim (bq needs --location for linked datasets):

bq query --location=$LOCATION --use_legacy_sql=false '
SELECT timestamp,
       JSON_VALUE(json_payload.tls_version) AS tls_version,
       JSON_VALUE(json_payload.kind) AS kind,
       JSON_VALUE(json_payload.proto) AS \`proto\`
FROM \`$PROJECT.$BQ_DATASET._AllLogs\`
WHERE JSON_VALUE(json_payload.message) = "request"
  AND JSON_VALUE(json_payload.user_agent) = "$UA"
ORDER BY timestamp DESC
LIMIT 20'

    The same SQL works in the console (Logging > Log Analytics) with the
    console's view path in the FROM clause instead:
    FROM \`$PROJECT.$LOCATION.$BUCKET._AllLogs\`

Troubleshooting empty pod logs (step 2):
  * kubectl logs deploy/tlsversion reads only ONE of the 2 replicas — use
    -l app=tlsversion (as above) to read both.
  * Only / and /v1/version.json log, and only over HTTPS. /healthcheck (what
    the probes hit) logs nothing, so with no real traffic the log is silent.
  * Check you're on the dg cluster: kubectl config current-context, and
    kubectl -n $NAMESPACE get pods -l app=tlsversion.
  * If the lines are logfmt (msg=request ...) rather than JSON, the running
    image predates the JSONHandler change.
EOF
