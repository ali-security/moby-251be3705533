package daemon // import "github.com/docker/docker/daemon"

import (
	"os"
	"path/filepath"
	"strings"
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

// realPath resolves p through any symlinks so comparisons against paths read
// back from /proc/self/fd (which are always fully resolved) are meaningful.
func realPath(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	assert.NilError(t, err)
	return resolved
}

// assertWithinRoot fails the test unless p is root or lies underneath it.
func assertWithinRoot(t *testing.T, root, p string) {
	t.Helper()
	rel, err := filepath.Rel(root, p)
	assert.NilError(t, err)
	escaped := rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel)
	assert.Assert(t, !escaped, "resolved mount target %q escaped the container root %q", p, root)
}

// TestOpenMountTarget covers the symlink-safe resolution of a bind-mount
// destination used by openContainerFS, which is the fix for CVE-2026-42306:
// "a race condition during mount setup allows a malicious container to redirect
// a bind mount onto an arbitrary path on the host filesystem".
//
// Before the fix, openContainerFS resolved the destination by name (via
// container.GetResourcePath) and passed that name to mount(2). The kernel
// re-resolves the target path at mount time, so a container process that
// replaces a component of the destination with a symlink in between wins the
// race and the bind mount lands outside the container root.
//
// After the fix the destination is opened through a root-scoped, symlink-safe
// lookup and the mount is performed onto /proc/self/fd/<fd>, which refers to
// the pinned inode and cannot be redirected by a later symlink swap.
func TestOpenMountTarget(t *testing.T) {
	t.Run("resolves within the container root", func(t *testing.T) {
		root := realPath(t, t.TempDir())
		assert.NilError(t, os.MkdirAll(filepath.Join(root, "mnt/data"), 0o755))

		targetFile, targetPath, err := openMountTarget(root, "mnt/data")
		assert.NilError(t, err)
		defer targetFile.Close()

		assert.Assert(t, strings.HasPrefix(targetPath, "/proc/self/fd/"),
			"mount target %q is not an fd path, a symlink swap could still redirect it", targetPath)

		resolved, err := os.Readlink(targetPath)
		assert.NilError(t, err)
		assert.Equal(t, resolved, filepath.Join(root, "mnt/data"))
		assertWithinRoot(t, root, resolved)
	})

	t.Run("symlinked destination cannot escape the root (CVE-2026-42306)", func(t *testing.T) {
		root := realPath(t, t.TempDir())
		outside := realPath(t, t.TempDir())
		assert.NilError(t, os.Mkdir(filepath.Join(outside, "host"), 0o755))

		// The container plants an absolute symlink pointing out of its own
		// root at the mount destination.
		assert.NilError(t, os.Symlink(filepath.Join(outside, "host"), filepath.Join(root, "evil")))

		// The exploit: resolving the destination by name follows the symlink
		// straight out of the container root, so mount(2) would bind onto the
		// host path.
		byName, err := filepath.EvalSymlinks(filepath.Join(root, "evil"))
		assert.NilError(t, err)
		assert.Equal(t, byName, filepath.Join(outside, "host"),
			"sanity check: a by-name mount target does follow the planted symlink")

		// The fix: the scoped lookup either refuses the escaping link or
		// re-roots it, but never yields a target outside the container root.
		targetFile, targetPath, err := openMountTarget(root, "evil")
		if err != nil {
			return
		}
		defer targetFile.Close()

		resolved, err := os.Readlink(targetPath)
		assert.NilError(t, err)
		assertWithinRoot(t, root, resolved)
	})

	t.Run("parent traversal is clamped to the root (CVE-2026-42306)", func(t *testing.T) {
		root := realPath(t, t.TempDir())

		targetFile, targetPath, err := openMountTarget(root, "../..")
		assert.NilError(t, err)
		defer targetFile.Close()

		resolved, err := os.Readlink(targetPath)
		assert.NilError(t, err)
		assert.Equal(t, resolved, root, "'..' in the destination walked above the container root")
	})

	t.Run("symlink swapped in after resolution cannot redirect the mount (CVE-2026-42306)", func(t *testing.T) {
		root := realPath(t, t.TempDir())
		outside := realPath(t, t.TempDir())
		assert.NilError(t, os.Mkdir(filepath.Join(outside, "host"), 0o755))
		assert.NilError(t, os.Mkdir(filepath.Join(root, "mnt"), 0o755))

		// The daemon resolves the destination inside the container root and
		// pins it with a file descriptor.
		targetFile, targetPath, err := openMountTarget(root, "mnt")
		assert.NilError(t, err)
		defer targetFile.Close()

		// The container wins the race: it moves the real destination aside and
		// drops a symlink to a host path in its place, exactly as it would
		// between GetResourcePath and mount(2) before the fix.
		assert.NilError(t, os.Rename(filepath.Join(root, "mnt"), filepath.Join(root, "moved")))
		assert.NilError(t, os.Symlink(filepath.Join(outside, "host"), filepath.Join(root, "mnt")))

		// The exploit: mounting onto the destination by name now lands on the
		// host path the container chose.
		byName, err := filepath.EvalSymlinks(filepath.Join(root, "mnt"))
		assert.NilError(t, err)
		assert.Equal(t, byName, filepath.Join(outside, "host"),
			"sanity check: the swapped symlink does redirect a by-name mount target")

		// The fix: the /proc/self/fd target still refers to the inode that was
		// resolved inside the container root, so the swap cannot redirect it.
		resolved, err := os.Readlink(targetPath)
		assert.NilError(t, err)
		assert.Equal(t, resolved, filepath.Join(root, "moved"),
			"the pinned mount target followed the symlink swapped in after resolution")
		assertWithinRoot(t, root, resolved)

		pinned, err := os.Stat(targetPath)
		assert.NilError(t, err)
		original, err := os.Stat(filepath.Join(root, "moved"))
		assert.NilError(t, err)
		assert.Assert(t, os.SameFile(pinned, original),
			"the mount target no longer refers to the inode resolved inside the container root")

		hostDir, err := os.Stat(filepath.Join(outside, "host"))
		assert.NilError(t, err)
		assert.Assert(t, !os.SameFile(pinned, hostDir),
			"the mount target was redirected to the host directory (CVE-2026-42306)")
	})
}
