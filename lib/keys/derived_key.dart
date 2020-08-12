import 'derivation_service.dart';
import 'derivation_strategy.dart';
import 'data_encryption_key.dart';
import 'derivation_artefacts.dart';

import 'encryption_key.dart';

/// An encryption key derived from a user-entered string using an algorithm such as Pbkdf2
class DerivedKey implements SymmetricKey {
  final DataEncryptionKey key;
  final DerivationArtefacts derivationArtefacts;

  /// Get the raw key
  get bytes {
    return key.bytes;
  }

  DerivedKey._({this.key, this.derivationArtefacts});
}

/// Provided a user-entered passphrase and artifacts serialized in cryppo's serialization format,
/// derive the data encryption key.
Future<DerivedKey> deriveKeyWithSerializedOptions(
    String passphrase, String serializedDerivationArtefacts) async {
  final DerivationArtefacts artefacts =
      DerivationArtefacts.fromSerialized(serializedDerivationArtefacts);
  final service = artefacts.strategy.toService();
  final keyBytes =
      await service.deriveKey(passphrase: passphrase, artefacts: artefacts);
  return DerivedKey._(
      key: DataEncryptionKey.loadFromBytes(keyBytes),
      derivationArtefacts: artefacts);
}

/// Provided a user-entered passphrase and a key derivation strategy,
/// derive a data encryption key with randomly generated derivation artefacts.
/// The key and artefacts can be serialized for transfer over the wire and storage.
Future<DerivedKey> deriveNewKeyFromString(
    String passphrase, DerivationStrategy strategy) async {
  final DerivationArtefacts artefacts = DerivationArtefacts.generate();
  final DerivationService service = strategy.toService();
  artefacts.strategy = strategy;

  final keyBytes =
      await service.deriveKey(artefacts: artefacts, passphrase: passphrase);
  return DerivedKey._(
      key: DataEncryptionKey.loadFromBytes(keyBytes),
      derivationArtefacts: artefacts);
}
