// Package sarif serializes Shinigami findings as SARIF 2.1.0.
package sarif

import (
 "encoding/json"
 "path/filepath"
 "strings"

 "github.com/azinamouto/shinigami/internal/scanner"
)

type report struct {
 Version string `json:"version"`
 Schema string `json:"$schema"`
 Runs []run `json:"runs"`
}
type run struct {
 Tool tool `json:"tool"`
 Results []result `json:"results"`
}
type tool struct { Driver driver `json:"driver"` }
type driver struct { Name string `json:"name"`; Version string `json:"version"`; Rules []rule `json:"rules"` }
type rule struct { ID string `json:"id"`; ShortDescription message `json:"shortDescription"` }
type message struct { Text string `json:"text"` }
type result struct {
 RuleID string `json:"ruleId"`
 Level string `json:"level"`
 Message message `json:"message"`
 Locations []location `json:"locations,omitempty"`
 PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}
type location struct { PhysicalLocation physical `json:"physicalLocation"` }
type physical struct { ArtifactLocation artifact `json:"artifactLocation"`; Region *region `json:"region,omitempty"` }
type artifact struct { URI string `json:"uri"` }
type region struct { StartLine int `json:"startLine"` }

func level(severity string) string {
 switch strings.ToUpper(severity) { case "HIGH", "CRITICAL": return "error"; case "MEDIUM": return "warning"; default: return "note" }
}

// Encode writes no source snippets or secret values. Findings must already be
// normalized and redacted by the scanner adapters.
func Encode(findings []scanner.Finding, version string) ([]byte, error) {
 rules := make([]rule,0)
 results := make([]result,0,len(findings))
 seen := make(map[string]bool)
 for _, f := range findings {
  if !seen[f.Rule] { rules=append(rules,rule{ID:f.Rule,ShortDescription:message{Text:f.Rule}}); seen[f.Rule]=true }
  r:=result{RuleID:f.Rule,Level:level(f.Severity),Message:message{Text:f.Message}}
  if f.ID!="" {r.PartialFingerprints=map[string]string{"shinigami/v1":f.ID}}
  if f.File!="" {
   path:=filepath.ToSlash(filepath.Clean(f.File))
   p:=physical{ArtifactLocation:artifact{URI:path}}
   if f.Line>0 {p.Region=&region{StartLine:f.Line}}
   r.Locations=[]location{{PhysicalLocation:p}}
  }
  results=append(results,r)
 }
 return json.MarshalIndent(report{Version:"2.1.0",Schema:"https://json.schemastore.org/sarif-2.1.0.json",Runs:[]run{{Tool:tool{Driver:driver{Name:"Shinigami",Version:version,Rules:rules}},Results:results}}},"","  ")
}
