package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Checkup runs the repository's own test command inside an isolated per-job
// checkout: {OPA_REVIEW_TMP}/{job}/primary. Family services pin their shared
// libraries with filesystem replace directives:
//
//	replace github.com/TheGrimmChester/open-auth-go => ../Open-Auth-Go
//
// Those siblings exist in a developer tree but not in the job layout, so the
// toolchain aborts before a single test runs:
//
//	auth_wire.go:7:2: …/open-auth-go@v0.0.0: replacement directory
//	../Open-Auth-Go does not exist
//
// The check then reported "OPA Checkup failed" for a tree whose tests pass
// locally. This file resolves those directives before the run, and reports the
// workspace as unprepared (neutral) rather than failing when it cannot.

// goModLocalReplace is one filesystem replace directive from go.mod.
type goModLocalReplace struct {
	Module string // github.com/TheGrimmChester/open-auth-go
	Rel    string // ../Open-Auth-Go
	Name   string // Open-Auth-Go
}

// replaceLine matches `mod [vX] => ./path [vY]` inside or outside a replace block.
var replaceLine = regexp.MustCompile(`^(?:replace\s+)?([^\s=]+)(?:\s+v\S+)?\s*=>\s*(\.[^\s]*)`)

// parseGoModLocalReplaces returns the filesystem replace directives in go.mod.
// Version-to-version replacements are ignored: only paths resolve on disk.
func parseGoModLocalReplaces(goMod []byte) []goModLocalReplace {
	var out []goModLocalReplace
	inBlock := false
	for _, raw := range strings.Split(string(goMod), "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "replace") && strings.HasSuffix(line, "("):
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		}
		if !inBlock && !strings.HasPrefix(line, "replace") {
			continue
		}
		m := replaceLine.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		rel := m[2]
		name := filepath.Base(filepath.Clean(rel))
		if name == "" || name == "." || name == ".." {
			continue
		}
		out = append(out, goModLocalReplace{Module: m[1], Rel: rel, Name: name})
	}
	return out
}

// checkupModuleSourceRoots lists host directories that may hold family module
// sources, most specific first. Operators set OPA_CHECKUP_MODULE_SRC (or the
// conventional FAMILY_ROOT) to the sibling checkout tree.
func checkupModuleSourceRoots() []string {
	var roots []string
	for _, env := range []string{"OPA_CHECKUP_MODULE_SRC", "FAMILY_ROOT", "OPA_FAMILY_SRC"} {
		for _, part := range strings.Split(os.Getenv(env), string(os.PathListSeparator)) {
			if p := strings.TrimSpace(part); p != "" && filepath.IsAbs(p) {
				roots = append(roots, filepath.Clean(p))
			}
		}
	}
	return roots
}

// checkupWorkspaceReport records how module replacements were resolved so the
// check run can explain itself without an operator reading container logs.
type checkupWorkspaceReport struct {
	Required   []string `json:"required,omitempty"`
	Satisfied  []string `json:"satisfied,omitempty"`
	Unresolved []string `json:"unresolved,omitempty"`
	SourceRoot string   `json:"source_root,omitempty"`
}

// Blocked reports whether the tree cannot build as checked out.
func (r checkupWorkspaceReport) Blocked() bool { return len(r.Unresolved) > 0 }

// Honesty renders an operator-facing explanation.
func (r checkupWorkspaceReport) Honesty() string {
	if !r.Blocked() {
		if len(r.Satisfied) == 0 {
			return ""
		}
		return fmt.Sprintf("resolved %d local module replacement(s) from %s: %s",
			len(r.Satisfied), nz(r.SourceRoot, "the job layout"), strings.Join(r.Satisfied, ", "))
	}
	return fmt.Sprintf("workspace not prepared — go.mod replaces %s with a directory outside the job checkout. "+
		"Mount the sibling module tree and point OPA_CHECKUP_MODULE_SRC at it; tests were not run.",
		strings.Join(r.Unresolved, ", "))
}

// prepareCheckupWorkspace resolves filesystem replace directives for treeRoot by
// materializing each target as a sibling of the checkout, so ../Name resolves
// inside the sandbox exactly as it does in a developer tree.
func prepareCheckupWorkspace(treeRoot string) checkupWorkspaceReport {
	var rep checkupWorkspaceReport
	treeRoot = filepath.Clean(treeRoot)
	goMod, err := os.ReadFile(filepath.Join(treeRoot, "go.mod"))
	if err != nil {
		return rep
	}
	reps := parseGoModLocalReplaces(goMod)
	if len(reps) == 0 {
		return rep
	}
	layout := filepath.Dir(treeRoot)
	roots := checkupModuleSourceRoots()
	for _, r := range reps {
		rep.Required = append(rep.Required, r.Name)
		target := filepath.Clean(filepath.Join(treeRoot, r.Rel))
		// Already present (developer tree or a previous run) and non-empty.
		if goModuleDirReady(target) {
			rep.Satisfied = append(rep.Satisfied, r.Name)
			continue
		}
		// Only materialize targets that land inside the job layout; a directive
		// pointing anywhere else is not something the runner should satisfy.
		if !pathUnder(target, layout) {
			rep.Unresolved = append(rep.Unresolved, r.Name+" (outside job layout)")
			continue
		}
		src := ""
		for _, root := range roots {
			cand := filepath.Join(root, r.Name)
			if goModuleDirReady(cand) {
				src = cand
				rep.SourceRoot = root
				break
			}
		}
		if src == "" {
			rep.Unresolved = append(rep.Unresolved, r.Name)
			continue
		}
		if err := copyGoModuleDir(src, target); err != nil {
			rep.Unresolved = append(rep.Unresolved, fmt.Sprintf("%s (%v)", r.Name, err))
			continue
		}
		rep.Satisfied = append(rep.Satisfied, r.Name)
	}
	return rep
}

// goModuleDirReady reports whether dir looks like a usable module checkout.
func goModuleDirReady(dir string) bool {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return false
	}
	gm, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil && gm.Size() > 0
}

// checkupModuleSkipDirs are never copied into a module sibling.
var checkupModuleSkipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, ".idea": true,
	"dist": true, "build": true, "coverage": true, ".next": true,
}

// copyGoModuleDir copies a module source tree. Sources are trusted family
// checkouts, but the walk still refuses symlinks so a link inside a source tree
// cannot pull host paths into the job layout.
func copyGoModuleDir(src, dst string) error {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if checkupModuleSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks, sockets, devices
		}
		return copyRegularFile(path, filepath.Join(dst, rel))
	})
}

func copyRegularFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// checkupModuleSiblingDirs lists module directories materialized next to the
// checkout, so the sandbox can bind them read-only.
func checkupModuleSiblingDirs(treeRoot string, rep checkupWorkspaceReport) []string {
	if len(rep.Satisfied) == 0 {
		return nil
	}
	layout := filepath.Dir(filepath.Clean(treeRoot))
	var out []string
	for _, name := range rep.Satisfied {
		dir := filepath.Join(layout, name)
		if !pathUnder(dir, layout) {
			continue
		}
		if goModuleDirReady(dir) {
			out = append(out, dir)
		}
	}
	return out
}

// purgeCheckupState removes runner state left inside the checkout by an earlier
// attempt. Stale .opa-checkup stdout captures otherwise leak between attempts on
// a reused layout and can be read as the current run's output.
func purgeCheckupState(workRoot string) {
	dir := filepath.Join(filepath.Clean(workRoot), ".opa-checkup")
	if !pathUnder(dir, filepath.Clean(workRoot)) {
		return
	}
	_ = os.RemoveAll(dir)
}
