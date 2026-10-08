package gateway

import "testing"

func TestDecodeConfigStructureSkipsRuntimeReadiness(t *testing.T) {
	doc := []byte(`{"config_version":1,"listen":"127.0.0.1:1","public_url":"https://g.invalid","tls_cert_file":"/nonexistent/c","tls_key_file":"/nonexistent/k","signing_key_file":"/nonexistent/s","database":"/nonexistent/db","profiles":[],"bots":[],"channels":[]}`)
	c, err := DecodeConfigStructure(doc)
	if err != nil || c.ConfigVersion != 1 {
		t.Fatalf("structure decode: %v", err)
	}
	if _, err := DecodeConfig(doc); err == nil {
		t.Fatal("DecodeConfig must still run Validate")
	}
	for _, bad := range []string{`{"config_version":1,"config_version":1,"profiles":[]}`, `{"config_version":1,"zzz":1,"profiles":[]}`, `{"config_version":1}`, `{"config_version":1,"profiles":null}`} {
		if _, err := DecodeConfigStructure([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
