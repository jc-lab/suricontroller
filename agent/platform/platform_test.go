package platform

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProbeOpenWrt(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.MkdirAll(filepath.Join(root, "sbin"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/openwrt_release"), []byte("DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.2'\nDISTRIB_ARCH='aarch64_cortex-a53'\n"), 0o644)
	os.WriteFile(filepath.Join(root, "etc/hostname"), []byte("gw\n"), 0o644)
	os.WriteFile(filepath.Join(root, "sbin/fw4"), []byte("#!/bin/sh\n"), 0o755)
	ex := ChrootExec{Root: root}
	info := Probe(context.Background(), HostFS{Root: root}, ex)
	if !info.OpenWrt || info.OSVersion != "24.10.2" || info.Arch != "aarch64_cortex-a53" || info.Hostname != "gw" || !info.Fw4 || info.Nft {
		t.Fatalf("info = %+v", info)
	}
}

func TestChrootExecFallback(t *testing.T) {
	ex := ChrootExec{Root: t.TempDir(), Fallback: LocalExec{}}
	out, err := ex.Run(context.Background(), "echo", []string{"hi"}, nil)
	if err != nil || string(out) != "hi\n" {
		t.Fatalf("fallback: %q %v", out, err)
	}
	if _, err := (ChrootExec{Root: t.TempDir()}).Run(context.Background(), "echo", nil, nil); err == nil {
		t.Fatal("expected not found without fallback")
	}
}

func TestInterfaceLoopback(t *testing.T) {
	st := Interface("lo")
	if !st.Present || !st.Up {
		t.Skip("no loopback")
	}
	if Interface("does-not-exist0").Present {
		t.Fatal("missing interface reported present")
	}
}
