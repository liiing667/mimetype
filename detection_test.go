package mimetype

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"
)

func mimeStrings(ms []*MIME) []string {
	ss := make([]string, len(ms))
	for i, m := range ms {
		ss[i] = m.String()
	}
	return ss
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The primary verdict of Analyze and AnalyzeReader must always be the same
// as what Detect and DetectReader return.
func TestAnalyzePrimaryParity(t *testing.T) {
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.data)

			d := Analyze(data)
			if want := Detect(data).String(); d.Primary().String() != want {
				t.Errorf("Analyze primary: expected: %s, got: %s", want, d.Primary())
			}
			if got := mimeStrings(d.Path()); got[len(got)-1] != d.Primary().String() {
				t.Errorf("Analyze path should end with the primary verdict: %v", got)
			}
			if got := d.Path()[0].String(); got != "application/octet-stream" {
				t.Errorf("Analyze path should start at the root, got: %s", got)
			}

			dr, err := AnalyzeReader(strings.NewReader(tc.data))
			if err != nil {
				t.Fatalf("AnalyzeReader: unexpected error: %s", err)
			}
			mr, err := DetectReader(strings.NewReader(tc.data))
			if err != nil {
				t.Fatalf("DetectReader: unexpected error: %s", err)
			}
			if dr.Primary().String() != mr.String() {
				t.Errorf("AnalyzeReader primary: expected: %s, got: %s", mr, dr.Primary())
			}
			if dr.Truncated() {
				t.Error("AnalyzeReader should not report truncation for inputs smaller than the read limit")
			}
		})
	}
}

// A ZIP whose entries satisfy both the APK and the JAR signatures.
// The first match in tree order (APK) wins the primary verdict; the JAR
// signature is reported as a conflict so callers can see every hit.
func TestAnalyzePolyglotApkJar(t *testing.T) {
	data, err := os.ReadFile("testdata/polyglot_apk_jar.zip")
	if err != nil {
		t.Fatal(err)
	}

	d := Analyze(data)
	if want := "application/vnd.android.package-archive"; d.Primary().String() != want {
		t.Errorf("primary: expected: %s, got: %s", want, d.Primary())
	}
	wantPath := []string{
		"application/octet-stream",
		"application/zip",
		"application/vnd.android.package-archive",
	}
	if got := mimeStrings(d.Path()); !equalStrings(got, wantPath) {
		t.Errorf("path: expected: %v, got: %v", wantPath, got)
	}
	wantConflicts := []string{"application/java-archive"}
	if got := mimeStrings(d.Conflicts()); !equalStrings(got, wantConflicts) {
		t.Errorf("conflicts: expected: %v, got: %v", wantConflicts, got)
	}
	if d.Truncated() {
		t.Error("truncated: expected: false")
	}
	if d.IsFallback() {
		t.Error("fallback: expected: false")
	}

	// The reader version must agree.
	dr, err := AnalyzeReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if dr.Primary().String() != d.Primary().String() {
		t.Errorf("AnalyzeReader primary: expected: %s, got: %s", d.Primary(), dr.Primary())
	}
	if got := mimeStrings(dr.Conflicts()); !equalStrings(got, wantConflicts) {
		t.Errorf("AnalyzeReader conflicts: expected: %v, got: %v", wantConflicts, got)
	}
}

// A ZIP archive embedding an uncompressed MP3 stream matches both the ZIP
// and the MP3 signatures at the root level. ZIP wins by tree order; the
// hidden MP3 signature is surfaced as a conflict.
func TestAnalyzePolyglotZipMp3(t *testing.T) {
	data, err := os.ReadFile("testdata/polyglot_mp3.zip")
	if err != nil {
		t.Fatal(err)
	}

	d := Analyze(data)
	if want := "application/zip"; d.Primary().String() != want {
		t.Errorf("primary: expected: %s, got: %s", want, d.Primary())
	}
	wantPath := []string{"application/octet-stream", "application/zip"}
	if got := mimeStrings(d.Path()); !equalStrings(got, wantPath) {
		t.Errorf("path: expected: %v, got: %v", wantPath, got)
	}
	wantConflicts := []string{"audio/mpeg"}
	if got := mimeStrings(d.Conflicts()); !equalStrings(got, wantConflicts) {
		t.Errorf("conflicts: expected: %v, got: %v", wantConflicts, got)
	}
}

// Truncated input must not be reported as a more specific type: signatures
// located past the cut cannot match, and the verdict falls back to the
// deepest type the available bytes support.
func TestAnalyzeTruncatedInput(t *testing.T) {
	data, err := os.ReadFile("testdata/polyglot_apk_jar.zip")
	if err != nil {
		t.Fatal(err)
	}

	// The polyglot fixture stores the JAR signature (the META-INF/MANIFEST.MF
	// entry name) at bytes 30-50 and the APK signature (the
	// AndroidManifest.xml entry name) at bytes 102-121. A cut must never
	// produce a verdict whose signature is not fully present before the cut.
	for _, tc := range []struct {
		cut         int
		primary     string
		conflicts   []string
		notReported []string
	}{
		// Only the ZIP local file header signature is present.
		{4, "application/zip", nil, []string{"application/vnd.android.package-archive", "application/java-archive"}},
		// The first entry name has not started yet.
		{30, "application/zip", nil, []string{"application/vnd.android.package-archive", "application/java-archive"}},
		// The META-INF/MANIFEST.MF name is cut one byte short.
		{49, "application/zip", nil, []string{"application/vnd.android.package-archive", "application/java-archive"}},
		// Boundary: the JAR signature is fully present, the APK one is not.
		{50, "application/java-archive", nil, []string{"application/vnd.android.package-archive"}},
		// The AndroidManifest.xml name is cut one byte short.
		{120, "application/java-archive", nil, []string{"application/vnd.android.package-archive"}},
		// Boundary: both signatures are fully present.
		{121, "application/vnd.android.package-archive", []string{"application/java-archive"}, nil},
	} {
		d := Analyze(data[:tc.cut])
		if d.Primary().String() != tc.primary {
			t.Errorf("cut at %d: primary: expected: %s, got: %s", tc.cut, tc.primary, d.Primary())
		}
		if got := mimeStrings(d.Conflicts()); !equalStrings(got, tc.conflicts) {
			t.Errorf("cut at %d: conflicts: expected: %v, got: %v", tc.cut, tc.conflicts, got)
		}
		for _, disallowed := range tc.notReported {
			if d.Primary().Is(disallowed) {
				t.Errorf("cut at %d: truncated input misreported as %s", tc.cut, d.Primary())
			}
			for _, c := range d.Conflicts() {
				if c.Is(disallowed) {
					t.Errorf("cut at %d: truncated input misreported conflict %s", tc.cut, c)
				}
			}
		}
		// Inputs cut by the caller, not by the read limit, are not truncated.
		if d.Truncated() {
			t.Errorf("cut at %d: truncated should be false for caller-truncated input", tc.cut)
		}
	}

	// A read limit smaller than the container signatures reports truncation
	// and falls back to the container type.
	SetLimit(4)
	defer SetLimit(defaultLimit)
	d := Analyze(data)
	if !d.Truncated() {
		t.Error("truncated: expected: true when input exceeds the read limit")
	}
	if want := "application/zip"; d.Primary().String() != want {
		t.Errorf("primary: expected: %s, got: %s", want, d.Primary())
	}
	if len(d.Conflicts()) != 0 {
		t.Errorf("conflicts: expected: none, got: %v", mimeStrings(d.Conflicts()))
	}

	dr, err := AnalyzeReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !dr.Truncated() {
		t.Error("AnalyzeReader truncated: expected: true when the reader has data past the read limit")
	}
	if want := "application/zip"; dr.Primary().String() != want {
		t.Errorf("AnalyzeReader primary: expected: %s, got: %s", want, dr.Primary())
	}
}

// When no signature matches, the verdict is the root
// "application/octet-stream" and the path contains only the root.
func TestAnalyzeFallback(t *testing.T) {
	d := Analyze([]byte{0x00, 0x01, 0x02, 0x03})
	if !d.IsFallback() {
		t.Errorf("fallback: expected: true, primary: %s", d.Primary())
	}
	if want := "application/octet-stream"; d.Primary().String() != want {
		t.Errorf("primary: expected: %s, got: %s", want, d.Primary())
	}
	if got := d.Path(); len(got) != 1 {
		t.Errorf("path: expected: root only, got: %v", mimeStrings(got))
	}
	if len(d.Conflicts()) != 0 {
		t.Errorf("conflicts: expected: none, got: %v", mimeStrings(d.Conflicts()))
	}
}

func TestAnalyzeReaderWonkyReaders(t *testing.T) {
	wonkyReaders := map[string]func(io.Reader) io.Reader{
		"DataErrReader": iotest.DataErrReader,
		"HalfReader":    iotest.HalfReader,
		"OneByteReader": iotest.OneByteReader,
	}

	data, err := os.ReadFile("testdata/polyglot_apk_jar.zip")
	if err != nil {
		t.Fatal(err)
	}

	for name, reader := range wonkyReaders {
		t.Run(name, func(t *testing.T) {
			d, err := AnalyzeReader(reader(bytes.NewReader(data)))
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if want := "application/vnd.android.package-archive"; d.Primary().String() != want {
				t.Errorf("primary: expected: %s, got: %s", want, d.Primary())
			}
			wantConflicts := []string{"application/java-archive"}
			if got := mimeStrings(d.Conflicts()); !equalStrings(got, wantConflicts) {
				t.Errorf("conflicts: expected: %v, got: %v", wantConflicts, got)
			}
		})
	}
}
