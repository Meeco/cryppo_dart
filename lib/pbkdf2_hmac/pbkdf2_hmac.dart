import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import '../keys/derivation_artefacts.dart';
import '../keys/derivation_service.dart';

/// Currently the only supported key derivation strategy
/// https://en.wikipedia.org/wiki/Pbkdf2
class Pbkdf2Hmac implements DerivationService {
  Future<List<int>> deriveKey(
      {required String passphrase, required DerivationArtefacts artefacts}) async {
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac(Sha256()),
      iterations: artefacts.iterations,
      bits: artefacts.length * 8,
    );

    final secretKey = SecretKey(utf8.encode(passphrase));

    return pbkdf2
        .deriveKey(secretKey: secretKey, nonce: artefacts.salt)
        .then((value) => value.extractBytes());
  }
}
