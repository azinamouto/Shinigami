package sarif

import (
 "bytes"
 "encoding/json"
 "testing"
 "github.com/azinamouto/shinigami/internal/scanner"
)
func TestEncodeRedactsAndLocates(t *testing.T) {
 findings:=[]scanner.Finding{{ID:"abc",Rule:"GITLEAKS/github-pat",Severity:"HIGH",File:"config/test.env",Line:3,Message:"Potential exposed credential",Remediation:"Rotate"}}
 b,err:=Encode(findings,"0.2.0-dev")
 if err!=nil {t.Fatal(err)}
 if bytes.Contains(b,[]byte("ghp_FAKE_SECRET")) {t.Fatal("secret leaked")}
 var obj map[string]any
 if err:=json.Unmarshal(b,&obj);err!=nil {t.Fatal(err)}
 if obj["version"]!="2.1.0" {t.Fatal("wrong SARIF version")}
 runs:=obj["runs"].([]any)
 results:=runs[0].(map[string]any)["results"].([]any)
 if len(results)!=1 {t.Fatalf("got %d results",len(results))}
}
func TestEncodeEmpty(t *testing.T) {
 b,err:=Encode(nil,"0.2.0-dev")
 if err!=nil || !bytes.Contains(b,[]byte(`"results": []`)) {t.Fatalf("invalid empty SARIF: %s %v",b,err)}
}
