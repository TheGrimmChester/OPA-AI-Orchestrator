package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// checkupAnnotation is a GitHub Check Run annotation payload fragment.
type checkupAnnotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"` // notice|warning|failure
	Message         string `json:"message"`
	Title           string `json:"title,omitempty"`
}

const githubCheckAnnotationLimit = 50

// checkupAnnotationsFromStepOutput converts stdout / JUnit / Checkstyle into
// annotations. Exit 0 alone is never enough when JUnit was expected — that is
// enforced in evaluatePostCondition; this only formats findings.
func checkupAnnotationsFromStepOutput(step checkupStep, stdout []byte, workRoot string) []checkupAnnotation {
	switch step.PostCondition.Kind {
	case "junit":
		path := filepath.Join(workRoot, step.PostCondition.Path)
		raw, err := os.ReadFile(path)
		if err != nil {
			return []checkupAnnotation{{
				Path: nz(step.PostCondition.Path, "."), StartLine: 1, EndLine: 1,
				AnnotationLevel: "failure", Title: step.ID,
				Message: "JUnit artifact missing: " + step.PostCondition.Path,
			}}
		}
		return junitToAnnotations(raw, step.ID)
	case "checkstyle":
		raw := stdout
		if step.PostCondition.Path != "" {
			if b, err := os.ReadFile(filepath.Join(workRoot, step.PostCondition.Path)); err == nil {
				raw = b
			}
		}
		return checkstyleToAnnotations(raw, step.ID)
	default:
		return nil
	}
}

type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
	// single suite root
	Name      string        `xml:"name,attr"`
	Tests     int           `xml:"tests,attr"`
	Failures  int           `xml:"failures,attr"`
	Errors    int           `xml:"errors,attr"`
	TestCases []junitCase   `xml:"testcase"`
}

type junitSuite struct {
	Name      string      `xml:"name,attr"`
	Tests     int         `xml:"tests,attr"`
	Failures  int         `xml:"failures,attr"`
	Errors    int         `xml:"errors,attr"`
	TestCases []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string         `xml:"name,attr"`
	Classname string         `xml:"classname,attr"`
	File      string         `xml:"file,attr"`
	Line      int            `xml:"line,attr"`
	Failure   *junitFailure  `xml:"failure"`
	Error     *junitFailure  `xml:"error"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

func junitToAnnotations(raw []byte, stepID string) []checkupAnnotation {
	var suites junitSuites
	if err := xml.Unmarshal(raw, &suites); err != nil {
		// try single testsuite root
		var one junitSuite
		if err2 := xml.Unmarshal(raw, &one); err2 != nil {
			return []checkupAnnotation{{
				Path: ".", StartLine: 1, EndLine: 1, AnnotationLevel: "failure",
				Title: stepID, Message: "unparseable JUnit XML",
			}}
		}
		suites.TestCases = one.TestCases
		suites.Suites = nil
	}
	cases := suites.TestCases
	for _, s := range suites.Suites {
		cases = append(cases, s.TestCases...)
	}
	var out []checkupAnnotation
	for _, tc := range cases {
		fail := tc.Failure
		if fail == nil {
			fail = tc.Error
		}
		if fail == nil {
			continue
		}
		path := nz(tc.File, classnameToPath(tc.Classname))
		line := tc.Line
		if line < 1 {
			line = 1
		}
		msg := nz(fail.Message, strings.TrimSpace(fail.Body))
		if msg == "" {
			msg = "test failed"
		}
		out = append(out, checkupAnnotation{
			Path: path, StartLine: line, EndLine: line,
			AnnotationLevel: "failure", Title: stepID + ": " + tc.Name,
			Message: truncateStr(msg, 2000),
		})
	}
	return out
}

func classnameToPath(cn string) string {
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return "."
	}
	return strings.ReplaceAll(cn, "\\", "/") + ".php"
}

type checkstyleFile struct {
	XMLName xml.Name          `xml:"checkstyle"`
	Files   []checkstyleFileN `xml:"file"`
}

type checkstyleFileN struct {
	Name   string            `xml:"name,attr"`
	Errors []checkstyleError `xml:"error"`
}

type checkstyleError struct {
	Line     int    `xml:"line,attr"`
	Column   int    `xml:"column,attr"`
	Severity string `xml:"severity,attr"`
	Message  string `xml:"message,attr"`
	Source   string `xml:"source,attr"`
}

func checkstyleToAnnotations(raw []byte, stepID string) []checkupAnnotation {
	var root checkstyleFile
	if err := xml.Unmarshal(raw, &root); err != nil {
		return nil
	}
	var out []checkupAnnotation
	for _, f := range root.Files {
		for _, e := range f.Errors {
			level := "warning"
			sev := strings.ToLower(e.Severity)
			if sev == "error" || sev == "fatal" {
				level = "failure"
			} else if sev == "info" || sev == "ignore" {
				level = "notice"
			}
			line := e.Line
			if line < 1 {
				line = 1
			}
			out = append(out, checkupAnnotation{
				Path: nz(f.Name, "."), StartLine: line, EndLine: line,
				AnnotationLevel: level, Title: nz(e.Source, stepID),
				Message: truncateStr(e.Message, 2000),
			})
		}
	}
	return out
}

// batchCheckupAnnotations splits into chunks of ≤50 for GitHub Checks API.
func batchCheckupAnnotations(all []checkupAnnotation) [][]checkupAnnotation {
	if len(all) == 0 {
		return nil
	}
	var batches [][]checkupAnnotation
	for i := 0; i < len(all); i += githubCheckAnnotationLimit {
		end := i + githubCheckAnnotationLimit
		if end > len(all) {
			end = len(all)
		}
		batches = append(batches, all[i:end])
	}
	return batches
}

func checkupAnnotationsToMaps(anns []checkupAnnotation) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(anns))
	for _, a := range anns {
		out = append(out, map[string]interface{}{
			"path": a.Path, "start_line": a.StartLine, "end_line": a.EndLine,
			"annotation_level": a.AnnotationLevel, "message": a.Message, "title": a.Title,
		})
	}
	return out
}

// countJUnitTests returns total testcase count from a JUnit XML blob.
func countJUnitTests(raw []byte) int {
	// Prefer counting <testcase> elements — attr totals can lie when empty.
	re := regexp.MustCompile(`(?i)<testcase\b`)
	n := len(re.FindAll(raw, -1))
	if n > 0 {
		return n
	}
	var suites junitSuites
	if xml.Unmarshal(raw, &suites) == nil {
		total := suites.Tests
		for _, s := range suites.Suites {
			total += s.Tests
		}
		return total
	}
	return 0
}
