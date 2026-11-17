package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestUnique(t *testing.T) {
	got := unique([]string{"apache2", "nginx", "apache2", "ssh", "nginx"})
	want := []string{"apache2", "nginx", "ssh"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
func TestManagedFileIdempotenceAndRestore(t *testing.T) {
	d := t.TempDir()
	file := filepath.Join(d, "config.ini")
	p := &plan{}
	body := marker + "expose_php = Off\n"
	if err := addFile(p, file, body); err != nil {
		t.Fatal(err)
	}
	if len(p.files) != 1 {
		t.Fatal("expected create change")
	}
	if err := atomicWrite(file, []byte(body)); err != nil {
		t.Fatal(err)
	}
	p = &plan{}
	if err := addFile(p, file, body); err != nil {
		t.Fatal(err)
	}
	if len(p.files) != 0 {
		t.Fatal("non-idempotent")
	}
	if err := os.WriteFile(file, []byte("unmanaged"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := addFile(&plan{}, file, body); err == nil {
		t.Fatal("overwrote unmanaged configuration")
	}
}
func TestRestore(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "new")
	if err := atomicWrite(p, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := restore([]change{{path: p, existed: false}}); err != nil {
		t.Fatal(err)
	}
	if exists(p) {
		t.Fatal("file not removed")
	}
}

func TestSSHEffectiveSettingParsing(t *testing.T) {
	// This test checks only the planned managed-file safety, not an actual sshd.
	d := t.TempDir()
	p := filepath.Join(d, "portguard-ssh.conf")
	planned := &plan{}
	body := marker + "DebianBanner no\n"
	if err := addFile(planned, p, body); err != nil || len(planned.files) != 1 {
		t.Fatalf("managed SSH file: %v, count %d", err, len(planned.files))
	}
	if err := os.WriteFile(p, []byte("DebianBanner no\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := addFile(&plan{}, p, body); err == nil {
		t.Fatal("should refuse overwrite of manually managed SSH file")
	}
}

func TestNginxStandardConfDIncludeParsing(t *testing.T) {
	tests := []struct {
		name string
		conf string
		want bool
	}{
		{
			name: "standard",
			conf: "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n",
			want: true,
		},
		{
			name: "multiple spaces",
			conf: "http {\n    include    /etc/nginx/conf.d/*.conf   ;\n}\n",
			want: true,
		},
		{
			name: "tabs",
			conf: "http {\n\tinclude\t/etc/nginx/conf.d/*.conf\t;\n}\n",
			want: true,
		},
		{
			name: "trailing comment",
			conf: "http {\n    include /etc/nginx/conf.d/*.conf; # managed includes\n}\n",
			want: true,
		},
		{
			name: "commented out",
			conf: "http {\n    # include /etc/nginx/conf.d/*.conf;\n}\n",
			want: false,
		},
		{
			name: "substring in comment",
			conf: "http {\n    server_tokens off; # include /etc/nginx/conf.d/*.conf;\n}\n",
			want: false,
		},
		{
			name: "different include",
			conf: "http {\n    include /etc/nginx/sites-enabled/*;\n}\n",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nginxHasStandardConfDInclude([]byte(tt.conf)); got != tt.want {
				t.Fatalf("nginxHasStandardConfDInclude() = %v, want %v", got, tt.want)
			}
		})
	}
}
