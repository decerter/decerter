// SPDX-License-Identifier: AGPL-3.0-only

// One HTTPS GET with dart:io's HttpClient, the TLS of Dart's BoringSSL inside libflutter.so, then the process exits.
// MainActivity hands over the intent extras as entrypoint arguments: the URL, the CA as base64 PEM and an id the
// e2e test finds the result line by in logcat (tag flutter).
import 'dart:convert';
import 'dart:io';

Future<void> main(List<String> arguments) async {
  final id = (arguments.length > 2) ? arguments[2] : '';

  try {
    final pem = base64Decode(arguments[1]);
    final context = SecurityContext(withTrustedRoots: false);
    context.setTrustedCertificatesBytes(pem);
    final client = HttpClient(context: context);
    // the test server's certificate has no IP address of the emulator's host: the chain is checked against the CA,
    // only a certificate that is the CA itself gets past the name check
    final der = base64Decode(LineSplitter.split(utf8.decode(pem)).where((line) => !line.startsWith('-----')).join());
    client.badCertificateCallback = (certificate, host, port) => _isEqual(certificate.der, der);
    final request = await client.getUrl(Uri.parse(arguments[0]));
    final response = await request.close();
    final body = await response.transform(utf8.decoder).join();
    client.close(force: true);
    print('decerter-flutter $id status ${response.statusCode} body $body');
  } catch (error) {
    print('decerter-flutter $id error $error');
  }

  exit(0);
}

bool _isEqual(List<int> first, List<int> second) {
  if (first.length != second.length) {
    return false;
  }

  for (var index = 0; index < first.length; index++) {
    if (first[index] != second[index]) {
      return false;
    }
  }

  return true;
}
