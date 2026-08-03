package daemon // import "github.com/docker/docker/daemon"

import (
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

// TestCreateIfNotExists covers the root-scoped createIfNotExists used by
// openContainerFS. Adapted from the upstream fix
// (moby commit 64a22d80b9) to the backport's filepath-securejoin signature
// createIfNotExists(rootPath, unsafePath, isDir) — upstream's test is written
// against Go 1.24 os.Root, which is unavailable on this go1.22 module.
//
// The escape sub-tests plant the path components a container process can swap
// for a symlink (an intermediate directory, the leaf, and "..") and assert that
// createIfNotExists never creates anything outside the container root. That is
// the escape described by CVE-2026-41568: "a race condition during docker cp
// mount setup allows a malicious container to create empty files or directories
// at arbitrary absolute paths on the host filesystem".
func TestCreateIfNotExists(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()

		err := createIfNotExists(dir, "tocreate", true)
		assert.NilError(t, err)

		fileinfo, err := os.Stat(filepath.Join(dir, "tocreate"))
		assert.NilError(t, err, "Did not create destination")
		assert.Assert(t, fileinfo.IsDir(), "Should have been a dir, seems it's not")

		err = createIfNotExists(dir, "tocreate", true)
		assert.NilError(t, err, "Should not fail if already exists")
	})
	t.Run("file", func(t *testing.T) {
		dir := t.TempDir()

		err := createIfNotExists(dir, "file/to/create", false)
		assert.NilError(t, err)

		fileinfo, err := os.Stat(filepath.Join(dir, "file/to/create"))
		assert.NilError(t, err, "Did not create destination")
		assert.Assert(t, !fileinfo.IsDir(), "Should have been a file, but created a directory")

		err = createIfNotExists(dir, "file/to/create", false)
		assert.NilError(t, err, "Should not fail if already exists")
	})
	t.Run("symlink is scoped to root (CVE-2026-41568)", func(t *testing.T) {
		// A symlink inside the root pointing outside it must not let a
		// create escape the container root. securejoin resolves the link
		// within root (RESOLVE_IN_ROOT), so nothing is written to `outside`.
		root := t.TempDir()
		outside := t.TempDir()
		assert.NilError(t, os.Symlink(outside, filepath.Join(root, "escape")))

		// Whether this returns an error or resolves the link within root, it
		// must never create the target in `outside` — that is the escape the
		// fix prevents.
		_ = createIfNotExists(root, "escape/pwned", true)

		_, statErr := os.Stat(filepath.Join(outside, "pwned"))
		assert.Assert(t, os.IsNotExist(statErr), "createIfNotExists escaped the root via symlink")
	})
	t.Run("symlinked leaf is not followed (CVE-2026-41568)", func(t *testing.T) {
		// The final path component is the component an attacker can most
		// easily swap for a symlink after GetResourcePath has resolved the
		// destination. The leaf is created with openat(O_NOFOLLOW) relative to
		// a pinned, root-scoped parent fd, so a symlinked leaf is refused
		// instead of followed.
		root := t.TempDir()
		outside := t.TempDir()

		assert.NilError(t, os.Symlink(filepath.Join(outside, "pwned"), filepath.Join(root, "leaf")))
		err := createIfNotExists(root, "leaf", false)
		assert.Assert(t, err != nil, "createIfNotExists should refuse to follow a symlinked leaf")

		_, statErr := os.Stat(filepath.Join(outside, "pwned"))
		assert.Assert(t, os.IsNotExist(statErr), "createIfNotExists escaped the root via a symlinked leaf")
	})
	t.Run("parent traversal is clamped to root (CVE-2026-41568)", func(t *testing.T) {
		// ".." components are clamped at the root rather than walking above
		// it, so an "arbitrary absolute path on the host" cannot be reached.
		root := t.TempDir()
		above := filepath.Dir(root)

		_ = createIfNotExists(root, "../pwned-dir", true)
		_, statErr := os.Stat(filepath.Join(above, "pwned-dir"))
		assert.Assert(t, os.IsNotExist(statErr), "createIfNotExists escaped the root via '..'")

		_ = createIfNotExists(root, "../pwned-file", false)
		_, statErr = os.Stat(filepath.Join(above, "pwned-file"))
		assert.Assert(t, os.IsNotExist(statErr), "createIfNotExists escaped the root via '..'")
	})
}
