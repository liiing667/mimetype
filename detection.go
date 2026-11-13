package mimetype

import (
	"io"
	"sync/atomic"
)

// Detection describes the outcome of analyzing an input: the primary MIME
// verdict, the full path of matched types, the conflicting signatures, and
// whether the input was truncated by the read limit.
//
// The selection rules are:
//   - Detectors run depth-first, in tree order. At each level the first
//     matching child is selected and the search continues underneath it.
//   - Any other child matching at the same level is a multi-signature
//     conflict. Conflicts are resolved to their own deepest match and
//     reported in tree order, but they never change the primary verdict.
//   - When no child matches, the current node is the verdict: a container
//     with no matching inner format is reported as the container itself.
//     When nothing matches at all, the verdict is the root
//     "application/octet-stream" and IsFallback reports true.
//   - Detectors never see bytes past the read limit (see SetLimit), so a
//     truncated input cannot produce a verdict more specific than what the
//     available bytes support.
type Detection struct {
	primary   *MIME
	path      []*MIME
	conflicts []*MIME
	truncated bool
}

// errDetection is returned from AnalyzeReader when err is not nil.
var errDetection = &Detection{primary: errMIME, path: []*MIME{errMIME}}

// Primary returns the main MIME verdict.
// It is always the same value Detect returns for the same input.
func (d *Detection) Primary() *MIME {
	return d.primary
}

// Path returns the chain of matched types, from the root
// "application/octet-stream" down to the primary verdict.
// The last element is always the primary verdict.
func (d *Detection) Path() []*MIME {
	return d.path
}

// Conflicts returns the alternative signatures that matched the input but
// were not selected as the primary verdict, in tree order. Each conflict is
// resolved to its own deepest match; conflicts nested inside a conflicting
// subtree are not reported.
//
// A polyglot file, for example a ZIP archive that also satisfies the JAR or
// MP3 signatures, is reported with "application/zip" (or a more specific
// ZIP-based format) as primary and the hidden signatures as conflicts.
func (d *Detection) Conflicts() []*MIME {
	return d.conflicts
}

// Truncated reports whether the input was cut at the read limit (see
// SetLimit). When true, signatures located past the limit were not evaluated
// and the verdict may be less specific than for the complete input.
func (d *Detection) Truncated() bool {
	return d.truncated
}

// IsFallback reports whether no signature matched the input and the primary
// verdict is the root "application/octet-stream".
func (d *Detection) IsFallback() bool {
	return d.primary.Is("application/octet-stream")
}

// Analyze detects the MIME type of the provided byte slice and returns the
// full detection: primary verdict, matched type path, and conflicting
// signatures.
//
// Analyze(in).Primary() is always the same as Detect(in).
func Analyze(in []byte) *Detection {
	// Using atomic because readLimit can be written at the same time in other goroutine.
	l := atomic.LoadUint32(&readLimit)
	truncated := l > 0 && len(in) > int(l)
	if truncated {
		in = in[:l]
	}

	mu.RLock()
	defer mu.RUnlock()
	primary, path, conflicts := root.matchAll(in, l)
	return &Detection{
		primary:   primary,
		path:      path,
		conflicts: conflicts,
		truncated: truncated,
	}
}

// AnalyzeReader is the reader version of Analyze.
//
// The primary verdict of AnalyzeReader is always the same as what
// DetectReader returns for the same input.
// Any error returned is related to the reading from the input reader.
//
// AnalyzeReader assumes the reader offset is at the start. If the input is an
// io.ReadSeeker you previously read from, it should be rewinded before detection:
//
//	reader.Seek(0, io.SeekStart)
func AnalyzeReader(r io.Reader) (*Detection, error) {
	var in []byte
	var err error
	truncated := false

	// Using atomic because readLimit can be written at the same time in other goroutine.
	l := atomic.LoadUint32(&readLimit)
	if l == 0 {
		in, err = io.ReadAll(r)
		if err != nil {
			return errDetection, err
		}
	} else {
		var n int
		in = make([]byte, l)
		// io.UnexpectedEOF means len(r) < len(in). It is not an error in this case,
		// it just means the input file is smaller than the allocated bytes slice.
		n, err = io.ReadFull(r, in)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return errDetection, err
		}
		in = in[:n]
		if err == nil {
			// The read buffer was filled exactly. Probe for one more byte to
			// find out whether the input continues past the read limit.
			var one [1]byte
			if _, err := r.Read(one[:]); err == nil {
				truncated = true
			}
		}
	}

	mu.RLock()
	defer mu.RUnlock()
	primary, path, conflicts := root.matchAll(in, l)
	return &Detection{
		primary:   primary,
		path:      path,
		conflicts: conflicts,
		truncated: truncated,
	}, nil
}
