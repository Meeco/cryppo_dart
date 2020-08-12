import 'dart:convert';

import 'encryption_artefacts.dart';
import 'encryption_strategy.dart';
import '../keys/derivation_artefacts.dart';

/// Container for encrypted data which may contain key deriviation artefacts.
/// Can be converted to Cryppo's serialization format by using the [serialize] method.
class EncryptionResult {
  EncryptionStrategy strategy;
  List<int> cipherText;
  EncryptionArtefacts encryptionArtefacts;
  DerivationArtefacts derivationArtefacts;

  /// Container for encrypted data which may contain key deriviation artefacts.
  /// Can be converted to Cryppo's serialization format by using the [serialize] method.
  EncryptionResult(
      {this.strategy,
      this.cipherText,
      this.encryptionArtefacts,
      this.derivationArtefacts})
      : assert(strategy != null),
        assert(cipherText != null);

  /// Decode a serialized encrypted string into its components.
  EncryptionResult.fromSerialized(String serializedPayload) {
    final decomposedPayload = serializedPayload.split(".");
    // Payload should contain the following parts:
    // 0. strategy: a [EncryptionStrategy]
    // 1. cipher text: a base64url encoded [Uint8List]
    // 2. serialised encryption artefacts: a string (optional)
    // 3. serialised derivation artefacts: a string (optional)
    if (!(decomposedPayload.length == 3 || decomposedPayload.length == 4)) {
      throw Exception(
          'Serialised encryption should contain 3 or 4 parts, depending on version');
    }
    strategy = encryptionStrategyFromString(decomposedPayload[0]);
    final cipherText = decomposedPayload[1];
    this.cipherText = base64Url.decode(cipherText);
    this.encryptionArtefacts =
        EncryptionArtefacts.fromSerialized(decomposedPayload[2]);
  }

  /// Converts the encryption result into Cryppo's serialization format for transfer over the wire.
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

  /// Serialize the encryption result
  @override
  String toString() {
    return serialize();
  }
}
