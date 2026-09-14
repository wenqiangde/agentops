package opscloudflare

import (
	"encoding/json"
	"testing"
)

func TestStripJSONTrailingCommasPreservesStringContent(t *testing.T) {
	input := []byte(`{"name":"example-worker","note":"literal,}","items":["literal,]",],}`)
	clean, err := stripJSONTrailingCommas(input)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Note  string   `json:"note"`
		Items []string `json:"items"`
	}
	if err := json.Unmarshal(clean, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Note != "literal,}" || len(decoded.Items) != 1 || decoded.Items[0] != "literal,]" {
		t.Fatalf("decoded=%+v", decoded)
	}
}
