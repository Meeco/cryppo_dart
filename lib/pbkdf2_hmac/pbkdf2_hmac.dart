import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import '../keys/derivation_artefacts.dart';
import '../keys/derivation_service.dart';

class Pbkdf2Hmac implements DerivationService {
  Future<List<int>> deriveKey(
      {String passphrase, DerivationArtefacts artefacts}) async {
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac(sha256),
      iterations: artefacts.iterations,
      bits: artefacts.length * 8,
    );
    return pbkdf2.deriveBits(
      utf8.encode(passphrase),
      nonce: Nonce(artefacts.salt),
    );
  }
}
