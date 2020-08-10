import 'derivation_service.dart';
import 'derivation_strategy.dart';
import 'data_encryption_key.dart';
import 'derivation_artefacts.dart';

import 'key.dart';

class DerivedKey implements SymmetricKey {
  final DataEncryptionKey key;
  final DerivationArtefacts derivationArtefacts;

  get bytes {
    return key.bytes;
  }

  DerivedKey._({this.key, this.derivationArtefacts});
}

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
