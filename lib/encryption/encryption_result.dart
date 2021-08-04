import 'dart:convert';

import 'encryption_artefacts.dart';
import 'encryption_strategy.dart';
import '../keys/derivation_artefacts.dart';

/// Container for encrypted data which may contain key deriviation artefacts.
/// Can be converted to Cryppo's serialization format by using the [serialize] method.
class EncryptionResult {
  late EncryptionStrategy strategy;
  late List<int> cipherText;
  late EncryptionArtefacts encryptionArtefacts;

  ///[derivationArtefacts] contains both derivation strategy and artefacts
  DerivationArtefacts? derivationArtefacts;

  EncryptionResult._(
    this.strategy,
    this.cipherText,
    this.encryptionArtefacts,
    this.derivationArtefacts,
  );

  /// Container for encrypted data which may contain key deriviation artefacts.
  /// Can be converted to Cryppo's serialization format by using the [serialize] method.
  EncryptionResult.fromComponents({
    required EncryptionStrategy strategy,
    required List<int> cipherText,
    required EncryptionArtefacts encryptionArtefacts,
    DerivationArtefacts? derivationArtefacts,
  }) : this._(
          strategy,
          cipherText,
          encryptionArtefacts,
          derivationArtefacts,
        );

  /// Decode a serialized encrypted string into its components.
  EncryptionResult.fromSerialized(String serializedPayload) {
    final decomposedPayload = serializedPayload.split(".");
    // Payload should contain the following parts:
    // 0. strategy: a [EncryptionStrategy]
    // 1. cipher text: a base64url encoded [Uint8List]
    // 2. serialised encryption artefacts: a string
    // 3. key derivation strategy name: a string (optional)
    // 4. serialised derivation artefacts: a string (optional)
    if (!(decomposedPayload.length == 3 || decomposedPayload.length == 5)) {
      throw Exception(
          'Serialised encryption should contain 3 or 5 parts, depending on key derivation');
    }
    strategy = encryptionStrategyFromString(decomposedPayload[0]);
    this.cipherText = base64Url.decode(decomposedPayload[1]);
    this.encryptionArtefacts =
        EncryptionArtefacts.fromSerialized(decomposedPayload[2]);
    if (decomposedPayload.length == 5) {
      this.derivationArtefacts = DerivationArtefacts.fromSerialized(
          '${decomposedPayload[3]}.${decomposedPayload[4]}');
    }
  }

  /// Converts the encryption result into Cryppo's serialization format for transfer over the wire.
  String serialize() {
    final encodedCipherText = base64Url.encode(cipherText);
    final serializedEncryptionArtefacts = encryptionArtefacts.serialize();
    var serializedString =
        '${strategy.encode()}.$encodedCipherText.$serializedEncryptionArtefacts';
    if (derivationArtefacts != null) {
      serializedString += '.${derivationArtefacts!.serialize()}';
    }
    return serializedString;
  }

  /// Serialize the encryption result
  @override
  String toString() {
    var result = '';

    result += 'Strategy: $strategy\n';
    result += 'Cipher Text: ${base64Url.encode(cipherText)}\n';
    result += 'Encryption Artefacts: ${encryptionArtefacts.serialize()}\n';
    result +=
        'Derivation Strategy and Artefacts: ${derivationArtefacts?.serialize()}\n';

    return result;
  }
}
