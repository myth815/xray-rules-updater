package syncer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func acknowledgedFixture(t *testing.T) Config {
	t.Helper()
	c := fixture(t)
	c.RequireApplyAck = true
	c.ApplyAckPath = filepath.Join(filepath.Dir(c.Baseline), "applied.json")
	return c
}

func acknowledge(t *testing.T, c Config, version string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"version": version, "run_id": "host-owned-test", "consumers": map[string]any{"xray": true, "mosdns": true}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.ApplyAckPath, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestApplyAcknowledgementBoundsPublicationAndRetention(t *testing.T) {
	c := acknowledgedFixture(t)
	a, err := Run(context.Background(), c)
	if err != nil || a.Status != "published" {
		t.Fatalf("first publication without predecessor: %+v %v", a, err)
	}
	if _, err := os.Stat(c.ApplyAckPath); !os.IsNotExist(err) {
		t.Fatal("publisher must not write host acknowledgement")
	}
	repeat, err := Run(context.Background(), c)
	if err != nil || repeat.Status != "unchanged" || repeat.RunID == a.RunID {
		t.Fatalf("same desired must allow host apply retry: %+v %v", repeat, err)
	}
	c.GeneratorVersion = "test-next"
	blocked, err := Run(context.Background(), c)
	if err == nil || blocked.ErrorCode != "apply_pending" {
		t.Fatalf("unacknowledged first publication accepted: %+v %v", blocked, err)
	}
	assertCurrent(t, c, a.Version)
	acknowledge(t, c, a.Version)
	b, err := Run(context.Background(), c)
	if err != nil || b.Status != "published" || b.Version == a.Version {
		t.Fatalf("acknowledged publication failed: %+v %v", b, err)
	}
	prev, err := pointer(c.PublishDir, "previous")
	if err != nil || prev != "versions/"+a.Version {
		t.Fatalf("active predecessor not retained: %s %v", prev, err)
	}
	// The host still uses A after publication B. Repeating B is permitted,
	// but publishing C must neither replace B nor prune the active A files.
	repeat, err = Run(context.Background(), c)
	if err != nil || repeat.Status != "unchanged" || repeat.Version != b.Version {
		t.Fatalf("pending current retry rejected: %+v %v", repeat, err)
	}
	c.GeneratorVersion = "test-third"
	blocked, err = Run(context.Background(), c)
	if err == nil || blocked.ErrorCode != "apply_pending" {
		t.Fatalf("pending second publication accepted: %+v %v", blocked, err)
	}
	assertCurrent(t, c, b.Version)
	if _, err := validVersion(c.PublishDir, "versions/"+a.Version); err != nil {
		t.Fatalf("unacknowledged active predecessor removed: %v", err)
	}
	dirs, err := os.ReadDir(filepath.Join(c.PublishDir, "versions"))
	if err != nil || len(dirs) != 2 {
		t.Fatalf("pending publication must not grow versions: %v %v", dirs, err)
	}
	acknowledge(t, c, b.Version)
	third, err := Run(context.Background(), c)
	if err != nil || third.Status != "published" {
		t.Fatalf("third publication after ack failed: %+v %v", third, err)
	}
	dirs, err = os.ReadDir(filepath.Join(c.PublishDir, "versions"))
	if err != nil || len(dirs) != 2 {
		t.Fatalf("acknowledged version retention unbounded: %v %v", dirs, err)
	}
	if _, err := os.Stat(filepath.Join(c.PublishDir, "versions", a.Version)); !os.IsNotExist(err) {
		t.Fatal("obsolete version remained after safe advancement")
	}
}

func TestMalformedApplyStateFailsClosed(t *testing.T) {
	for _, body := range []string{"", "{", "[]", `{}`, `{"version":null}`, `{"version":123}`, `{"version":"../escape"}`,
		`{"version":"first","version":"second"}`, `{"version":"valid"} {}`, strings.Repeat("x", (64<<10)+1)} {
		t.Run("state-"+hash([]byte(body))[:8], func(t *testing.T) {
			c := acknowledgedFixture(t)
			a, err := Run(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(c.ApplyAckPath, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := Run(context.Background(), c)
			if err == nil || s.ErrorCode != "apply_state_invalid" {
				t.Fatalf("malformed state accepted even for unchanged desired: %+v %v", s, err)
			}
			assertCurrent(t, c, a.Version)
		})
	}
}

func TestApplyStateSymlinkAndStateWithoutCurrentRejected(t *testing.T) {
	c := acknowledgedFixture(t)
	target := filepath.Join(filepath.Dir(c.Baseline), "target.json")
	if err := os.WriteFile(target, []byte(`{"version":"valid"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, c.ApplyAckPath); err != nil {
		t.Fatal(err)
	}
	s, err := Run(context.Background(), c)
	if err == nil || s.ErrorCode != "apply_state_invalid" {
		t.Fatalf("symlink acknowledgement accepted: %+v %v", s, err)
	}
	if err := os.Remove(c.ApplyAckPath); err != nil {
		t.Fatal(err)
	}
	acknowledge(t, c, "stale-publication")
	s, err = Run(context.Background(), c)
	if err == nil || s.ErrorCode != "apply_state_without_current" {
		t.Fatalf("stale acknowledgement without current accepted: %+v %v", s, err)
	}
}

func TestPendingAckPreservesUnreferencedActiveVersion(t *testing.T) {
	c := acknowledgedFixture(t)
	a, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a host recovery state whose actual active data is outside both
	// pointers. The publisher must preserve it and block a different release.
	orphanName := "host-active-old"
	orphan := filepath.Join(c.PublishDir, "versions", orphanName)
	if err := os.Mkdir(orphan, 0700); err != nil {
		t.Fatal(err)
	}
	manifest, err := validVersion(c.PublishDir, "versions/"+a.Version)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Version = orphanName
	for name := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(c.PublishDir, "versions", a.Version, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(orphan, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	body, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(orphan, "manifest.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	acknowledge(t, c, orphanName)
	s, err := Run(context.Background(), c)
	if err != nil || s.Status != "unchanged" {
		t.Fatalf("host retry failed: %+v %v", s, err)
	}
	if _, err := validVersion(c.PublishDir, "versions/"+orphanName); err != nil {
		t.Fatalf("host-active orphan pruned: %v", err)
	}
	c.GeneratorVersion = "next"
	s, err = Run(context.Background(), c)
	if err == nil || s.ErrorCode != "apply_pending" {
		t.Fatalf("new version admitted with unknown active version: %+v %v", s, err)
	}
}

func TestBaselineDirectoryAndApplyAckConfig(t *testing.T) {
	c := fixture(t)
	c.Baseline, c.BaselineDirectory = "", "live-xray"
	c.RequireApplyAck = true
	body, _ := json.Marshal(c)
	base := t.TempDir()
	got, err := LoadConfig(body, base)
	if err != nil || got.Baseline != "" || got.BaselineDirectory != filepath.Join(base, "live-xray") || got.ApplyAckPath != filepath.Join(base, "applied.json") || got.ApplyTransactionPath != filepath.Join(base, "transaction.json") {
		t.Fatalf("directory and ack paths: %+v %v", got, err)
	}
	c.Baseline = "also-baseline.json"
	if err := c.validate(); err == nil {
		t.Fatal("both baseline inputs accepted")
	}
	c.Baseline, c.BaselineDirectory = "", ""
	if err := c.validate(); err == nil {
		t.Fatal("missing baseline input accepted")
	}
	c = fixture(t)
	c.ApplyAckPath = "applied.json"
	if err := c.validate(); err == nil {
		t.Fatal("ack path without required acknowledgement accepted")
	}
}

func TestHostTransactionHoldsProducerAfterNewAcknowledgement(t *testing.T) {
	c := acknowledgedFixture(t)
	// ApplyTransactionPath normally defaults during LoadConfig/Run. Set it
	// explicitly here because the host test creates its file between runs.
	c.ApplyTransactionPath = filepath.Join(filepath.Dir(c.ApplyAckPath), "transaction.json")
	a, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	acknowledge(t, c, a.Version)
	c.GeneratorVersion = "second"
	b, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	transaction, _ := json.Marshal(map[string]any{"run_id": "host-transaction", "desired_version": b.Version, "old_applied_version": a.Version})
	if err := os.WriteFile(c.ApplyTransactionPath, transaction, 0600); err != nil {
		t.Fatal(err)
	}
	// The host writes B's ack before finishing Nginx commit/bookkeeping. The
	// transaction must keep generation held and A available for rollback.
	acknowledge(t, c, b.Version)
	same, err := Run(context.Background(), c)
	if err != nil || same.Status != "unchanged" {
		t.Fatalf("same desired retry during transaction: %+v %v", same, err)
	}
	c.GeneratorVersion = "third"
	blocked, err := Run(context.Background(), c)
	if err == nil || blocked.ErrorCode != "apply_transaction_pending" {
		t.Fatalf("transaction did not hold producer: %+v %v", blocked, err)
	}
	if _, err := validVersion(c.PublishDir, "versions/"+a.Version); err != nil {
		t.Fatalf("transaction rollback data removed: %v", err)
	}
	if err := os.Remove(c.ApplyTransactionPath); err != nil {
		t.Fatal(err)
	}
	third, err := Run(context.Background(), c)
	if err != nil || third.Status != "published" {
		t.Fatalf("completed transaction did not release producer: %+v %v", third, err)
	}
	dirs, err := os.ReadDir(filepath.Join(c.PublishDir, "versions"))
	if err != nil || len(dirs) != 2 {
		t.Fatalf("post-transaction retention: %v %v", dirs, err)
	}
}

func TestMalformedHostTransactionFailsClosed(t *testing.T) {
	c := acknowledgedFixture(t)
	c.ApplyTransactionPath = filepath.Join(filepath.Dir(c.ApplyAckPath), "transaction.json")
	a, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	acknowledge(t, c, a.Version)
	for _, body := range []string{"", "{", `{}`, `{"run_id":"valid","desired_version":"../escape"}`, `{"run_id":"one","run_id":"two","desired_version":"valid"}`} {
		if err := os.WriteFile(c.ApplyTransactionPath, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		s, err := Run(context.Background(), c)
		if err == nil || s.ErrorCode != "apply_state_invalid" {
			t.Fatalf("bad transaction accepted: %+v %v", s, err)
		}
		assertCurrent(t, c, a.Version)
	}
}
