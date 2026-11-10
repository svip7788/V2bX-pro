package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpsertMachineMultiSite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{
  // 旧 Nodes 模式
  "Log": {"Level": "info"},
  "Nodes": [{"ApiHost": "http://old", "NodeID": 1}]
}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	a := MachineConfig{APIHost: "https://a.example.com/", MachineID: 1, Token: "ta", Core: "auto"}
	if act, err := UpsertMachine(path, a); err != nil || act != MachineCreated {
		t.Fatalf("create: %v %v", act, err)
	}
	b := MachineConfig{APIHost: "https://b.example.com", MachineID: 1, Token: "tb", Core: "xray"}
	if act, err := UpsertMachine(path, b); err != nil || act != MachineAdded {
		t.Fatalf("add: %v %v", act, err)
	}
	a.Token = "ta2"
	if act, err := UpsertMachine(path, a); err != nil || act != MachineUpdated {
		t.Fatalf("update: %v %v", act, err)
	}
	if act, _ := UpsertMachine(path, b); act != MachineUpdated {
		t.Fatalf("re-set extra should update, got %s", act)
	}

	c := New()
	if err := c.LoadFromPath(path); err != nil {
		t.Fatal(err)
	}
	if len(c.NodeConfig) != 0 {
		t.Fatalf("legacy Nodes should be dropped on first machine install")
	}
	ms := c.Machines()
	if len(ms) != 2 || ms[0].APIHost != "https://a.example.com" || ms[0].Token != "ta2" || ms[1].APIHost != "https://b.example.com" {
		t.Fatalf("unexpected machines: %+v", ms)
	}

	na, _ := ms[0].NodeConfig(3, "anytls")
	nb, _ := ms[1].NodeConfig(3, "anytls")
	if na.Options.CertConfig.CertFile == nb.Options.CertConfig.CertFile {
		t.Fatalf("same node id on two panels must not share cert file: %s", na.Options.CertConfig.CertFile)
	}
	if !strings.HasSuffix(na.Options.CertConfig.CertFile, "cert/node3.crt") {
		t.Fatalf("primary cert path should stay unchanged: %s", na.Options.CertConfig.CertFile)
	}
	if na.ApiConfig.APIHost == nb.ApiConfig.APIHost {
		t.Fatalf("node api hosts should differ")
	}

	if found, err := RemoveMachine(path, "https://a.example.com"); err != nil || !found {
		t.Fatalf("remove: %v %v", found, err)
	}
	c = New()
	if err := c.LoadFromPath(path); err != nil {
		t.Fatal(err)
	}
	if ms := c.Machines(); len(ms) != 1 || ms[0].APIHost != "https://b.example.com" || c.MachineConfig == nil {
		t.Fatalf("extra should be promoted to primary: %+v", ms)
	}
	if found, _ := RemoveMachine(path, "https://none"); found {
		t.Fatalf("removing unknown panel should report not found")
	}
}

func TestMachinesDedupAndCores(t *testing.T) {
	c := &Conf{
		MachineConfig:  &MachineConfig{APIHost: "https://a", MachineID: 1, Token: "t", Core: "sing"},
		MachineConfigs: []*MachineConfig{{APIHost: "https://A/", MachineID: 2, Token: "t"}, {APIHost: "https://b", MachineID: 0}},
	}
	if ms := c.Machines(); len(ms) != 1 {
		t.Fatalf("duplicate/disabled machines should be skipped, got %d", len(ms))
	}
	if cores := MachineCoreConfigs(nil); len(cores) != 1 || cores[0].Type != "xray" || cores[0].XrayConfig == nil {
		t.Fatalf("machine mode should start a single xray core, got %+v", cores)
	}
	existing := []CoreConfig{{Type: "xray", Name: "x"}}
	if cores := MachineCoreConfigs(existing); len(cores) != 1 || cores[0].Name != "x" {
		t.Fatalf("hand-written Cores should be kept, got %+v", cores)
	}
}
