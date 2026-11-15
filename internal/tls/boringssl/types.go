// SPDX-License-Identifier: AGPL-3.0-only

package boringssl

// Offset holds the per-release (Conscrypt) or per-revision (static builds), per-architecture BoringSSL offsets the
// ssl_log_secret uprobe reads. ssl_log_secret gets the SSL * and the secret as arguments, so only the path to the
// client_random is needed: S3 is the offset of the SSL3_STATE pointer in ssl_st and ClientRandom the offset of
// client_random in SSL3_STATE. Version is the negotiated protocol version, in ssl_st up to Android 15, in SSL3_STATE
// from Android 16 on and in the BoringSSL of Flutter's Dart (VersionInS3); the uprobe checks it against the version the
// label implies, so a library with another layout is reported instead of read.
type Offset struct {
	Version      uint64
	VersionInS3  bool
	S3           uint64
	ClientRandom uint64
}

// where a library is: Path is the file a uprobe attaches to, Entry the library's name inside an apk, empty for a library
// file of its own; Offset and Size are the ELF's bytes in Path, Offset is 0 for a library file of its own
type LibraryFile struct {
	Path   string
	Entry  string
	Offset uint64
	Size   uint64
}

// a libflutter.so decerter can hook: where it is, the Dart version the engine prints, the engine revision when the table knows
// it, the BoringSSL revision and offsets of the Dart version, and the file offset of ssl_log_secret in File.Path with the
// number of key log labels that led to it
type FlutterLibrary struct {
	File        LibraryFile
	DartVersion string
	Engine      string
	Flutter     []string
	Revision    string
	Offset      Offset
	LogSecret   uint64
	Labels      int
}

// a Chromium library decerter can hook (Chrome, Trichrome, WebView or Cronet): where it is, what it is by its name, its version, the BoringSSL revision and
// offsets of the version's branch, and the file offset of ssl_log_secret in File.Path with the number of key log labels that led to it
type ChromiumLibrary struct {
	File      LibraryFile
	Product   string
	Version   string
	Revision  string
	Offset    Offset
	LogSecret uint64
	Labels    int
}

// patch numbers First to Last of a Chromium branch (MAJOR.0.BUILD) whose DEPS pin the same BoringSSL revision
type chromiumRange struct {
	First    int
	Last     int
	Revision string
}

// one Dart version of the generated table: the BoringSSL revision the Flutter engine builds with it, the Flutter releases
// and engine revisions that were generated with it
type dartRelease struct {
	Revision string
	Flutter  []string
	Engines  []string
}

// BoringSSL revisions with equal offsets, per architecture
type revisionOffset struct {
	Revisions []string
	Offsets   map[string]Offset
}
