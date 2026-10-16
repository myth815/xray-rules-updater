package syncer

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type applyAckError struct{ code string }

func (e *applyAckError) Error() string { return e.code }

// readApplyAck reads a small host-owned completion record. The publisher never
// writes it: the host acknowledges only after all required consumers pass.
// Extra metadata is allowed, but ambiguous duplicate keys and malformed state
// fail closed. O_NOFOLLOW prevents replacing the trusted file with a symlink.
func readHostState(path string) (state map[string]json.RawMessage, present bool, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	invalid := &applyAckError{"apply_state_invalid"}
	if err != nil {
		return nil, false, invalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<10 {
		return nil, true, invalid
	}
	dec := json.NewDecoder(io.LimitReader(f, (64<<10)+1))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return nil, true, invalid
	}
	state = map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		if _, duplicate := state[key]; err != nil || !ok || duplicate {
			return nil, true, invalid
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return nil, true, invalid
		}
		state[key] = value
	}
	last, err := dec.Token()
	if err != nil || last != json.Delim('}') {
		return nil, true, invalid
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, true, invalid
	}
	return state, true, nil
}

func readApplyAck(c Config) (version string, present bool, err error) {
	state, present, err := readHostState(c.ApplyAckPath)
	if err != nil || !present {
		return "", present, err
	}
	if json.Unmarshal(state["version"], &version) != nil || !identifier.MatchString(version) {
		return "", true, &applyAckError{"apply_state_invalid"}
	}
	return version, true, nil
}

// A transaction holds generation through the acknowledgement/rollback window.
// Without it, a just-written acknowledgement could permit another publication
// to prune the pre-transaction rollback data before host commit completes.
func applyTransactionHeld(c Config) (bool, error) {
	state, present, err := readHostState(c.ApplyTransactionPath)
	if err != nil || !present {
		return present, err
	}
	var desired, runID string
	if json.Unmarshal(state["desired_version"], &desired) != nil || !identifier.MatchString(desired) ||
		json.Unmarshal(state["run_id"], &runID) != nil || !identifier.MatchString(runID) {
		return true, &applyAckError{"apply_state_invalid"}
	}
	return true, nil
}

// checkApplyAck permits retrying the same desired publication while the host
// applies it. A different publication requires acknowledgement of current, so
// an older active version remains previous until application has succeeded.
// An empty desired is an inspection before generation, not permission to
// publish. Its bool reports whether startup orphan pruning is safe.
func checkApplyAck(c Config, current, desired string) (bool, error) {
	if !c.RequireApplyAck {
		return true, nil
	}
	version, present, err := readApplyAck(c)
	if err != nil {
		return false, err
	}
	held, err := applyTransactionHeld(c)
	if err != nil {
		return false, err
	}
	if held {
		if desired == "" || (current != "" && desired == current) {
			return false, nil
		}
		return false, &applyAckError{"apply_transaction_pending"}
	}
	if current == "" {
		if present {
			return false, &applyAckError{"apply_state_without_current"}
		}
		return true, nil // The first publication has no active predecessor.
	}
	if present && version == filepath.Base(current) {
		return true, nil
	}
	if desired == "" || desired == current {
		return false, nil
	}
	return false, &applyAckError{"apply_pending"}
}

// pruneApplied retains the fixed current/previous pair. If host state refers
// elsewhere (or is absent/corrupt), it deletes no versions rather than guessing
// which files a consumer uses. Publication admission then blocks further growth
// until the host completes or repairs the pending application.
func pruneApplied(c Config) error {
	if !c.RequireApplyAck {
		return prune(c.PublishDir)
	}
	held, err := applyTransactionHeld(c)
	if err != nil || held {
		return err
	}
	version, present, err := readApplyAck(c)
	if err != nil {
		return err
	}
	if !present {
		current, err := pointer(c.PublishDir, "current")
		if err != nil {
			return err
		}
		if current == "" {
			return prune(c.PublishDir) // No acknowledged predecessor can be active.
		}
		return nil
	}
	for _, name := range []string{"current", "previous"} {
		target, err := pointer(c.PublishDir, name)
		if err != nil {
			return err
		}
		if target != "" && filepath.Base(target) == version {
			return prune(c.PublishDir)
		}
	}
	return errors.New("apply state does not match retained publications")
}
