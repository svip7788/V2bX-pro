package conf

import "testing"

func TestNewUsesWarningLogLevel(t *testing.T) {
	c := New()
	if c.LogConfig.Level != "warning" {
		t.Fatalf("expected warning log level, got %q", c.LogConfig.Level)
	}
}

func TestXrayDefaultsFavorHighConcurrency(t *testing.T) {
	c := NewXrayConfig()
	if c.ConnectionConfig.BufferSize != 32 {
		t.Fatalf("expected buffer size 32, got %d", c.ConnectionConfig.BufferSize)
	}

	o := NewXrayOptions()
	if o.DisableSniffing {
		t.Fatal("expected xray sniffing to be enabled by default")
	}
}
