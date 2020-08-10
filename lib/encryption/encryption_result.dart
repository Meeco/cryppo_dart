import 'dart:convert';

import 'encryption_artefacts.dart';
import 'encryption_strategy.dart';
import '../keys/derivation_artefacts.dart';

class EncryptionResult {
  EncryptionStrategy strategy;
  List<int> cipherText;
  EncryptionArtefacts encryptionArtefacts;
  DerivationArtefacts derivationArtefacts;

  EncryptionResult(
      {this.strategy,
      this.cipherText,
      this.encryptionArtefacts,
      this.derivationArtefacts})
      : assert(strategy != null),
        assert(cipherText != null);

  EncryptionResult.fromSerialized(String serializedPayload) {
    final decomposedPayload = serializedPayload.split(".");
    if (!(decomposedPayload.length == 3 || decomposedPayload.length == 4)) {
      throw Exception(
          'Serialised encryption should contain 3 or 4 parts, depending on version');
    }
    strategy = encryptionStrategyFromString(decomposedPayload[0]);
    final cipherText = decomposedPayload[1];
    this.cipherText = base64Url.decode(cipherText);
  }

  String serialize() {
    final encodedCipherText = base64Url.encode(cipherText);
    final serializedArtefacts = encryptionArtefacts.serialize();
    var serializedString =
        '${strategy.encode()}.$encodedCipherText.$serializedArtefacts';
    if (derivationArtefacts != null) {
      serializedString += '.${derivationArtefacts.serialize()}';
    }
    return serializedString;
  }

  @override
  String toString() {
    return serialize();
  }
}
