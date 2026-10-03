package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAmazonLinuxDetectionAndEndOfLifeNotice(t *testing.T) {
	for _, release := range []string{"2", "2023"} {
		t.Run(release, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"etc", "var/lib/rpm"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=amzn\nVERSION_ID=\""+release+"\"\nID_LIKE=fedora\n"), 0600)
			// Both database formats supported by the existing bounded RPM reader.
			if release == "2" {
				os.WriteFile(filepath.Join(root, "var/lib/rpm/Packages"), bdbFixture(rpmTestHeader()), 0600)
			} else {
				db, wal := sqliteFixture(t)
				os.WriteFile(filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"), db, 0600)
				os.WriteFile(filepath.Join(root, "var/lib/rpm/rpmdb.sqlite-wal"), wal, 0600)
			}
			result, err := Host(context.Background(), root, "openssl-libs", false)
			if err != nil || len(result.Components) != 1 {
				t.Fatalf("%+v %v", result, err)
			}
			if !bytes.Contains([]byte(result.Components[0].PURL), []byte("distro=amzn-"+release)) {
				t.Fatal("Amazon identity lost")
			}
			b, err := Marshal(result, "test", "test", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			var bom map[string]any
			if err = json.Unmarshal(b, &bom); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(b, []byte("complete-for-selected-inputs")) {
				t.Fatal("support notice changed inventory completeness")
			}
			if bytes.Contains(b, []byte("AMAZON_LINUX_2_END_OF_LIFE")) != (release == "2") {
				t.Fatal("wrong support notice")
			}
		})
	}
	if _, _, err := parseOSRelease([]byte("ID=fedora\nID_LIKE=amzn\nVERSION_ID=2023\n")); err == nil {
		t.Fatal("ID_LIKE must not impersonate Amazon Linux")
	}
}
