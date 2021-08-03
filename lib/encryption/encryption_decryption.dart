import 'dart:typed_data';

import '../keys/data_encryption_key.dart';
import '../keys/derivation_strategy.dart';
import '../keys/derived_key.dart';
import '../keys/encryption_key.dart';
import 'encryption_result.dart';
import 'encryption_strategy.dart';

typedef DecryptionMethod = Future<Uint8List> Function(
    String serialized, DataEncryptionKey key);

/// Provided an encrypted+serialized string (in Cryppo's encryption serialization format)
/// and a [Key] (the type of which depends on the type of encryption used)
/// return the decrypted binary data.
Future<List<int>> decryptWithKey({dynamic encrypted, required EncryptionKey key}) async {
  if (encrypted is String) {
    return _decryptSerialized(encrypted, key);
  } else if (encrypted is EncryptionResult) {
    return encrypted.strategy
        .toService()
        .decryptEncryptionResultWithKey(encrypted, key);
  } else {
    throw Exception(
        'encryptedObject is neither a serialised String or an EncryptionResult');
  }
}

/// Provided an encrypted+serialized string (in Cryppo's encryption serialization format
/// which includes serialized key derivation artefacts), derive the key (using the entered
/// passphrase) and return the decrypted binary data.
Future<List<int>> decryptWithKeyDerivedFromString(
    {required String serialized, required String passphrase}) async {
  final parts = serialized.split('.');

  if (parts.length != 5) {
    throw Exception('Invalid encrypted serialized data - expected 5 parts');
  }

  /// Serialization in the following segments:
  /// parts[0] = encryptionStrategy
  /// parts[1] = encryptedData
  /// parts[2] = encryptionArtefacts
  /// (When using a derived key:)
  /// parts[3] = keyDerivationStrategy
  /// parts[4] = keyDerivationArtefacts

  final derivedKey = await deriveKeyWithSerializedOptions(
      passphrase, parts.sublist(parts.length - 2).join('.'));
  return _decryptSerialized(parts.sublist(0, 3).join('.'), derivedKey.key);
}

/// Encrypts [data] with [EncryptionKey], data must be provided in bytes
/// A [EncryptionKey] can be a symmetrical key or a key pair, which corresponds to
/// AES or RSA [EncryptionStrategy]
Future<EncryptionResult> encryptWithKey({
  required EncryptionStrategy encryptionStrategy,
  required EncryptionKey key,
  required List<int> data,
}) {
  return _encrypt(data: data as Uint8List, encryptionStrategy: encryptionStrategy, key: key);
}

/// Encrypts [data] with a key derived from [passphrase]
/// using [keyDerivationStrategy], data must be provided in bytes
/// A [EncryptionKey] can be a symmetrical key or a key pair, which corresponds to
/// AES or RSA [EncryptionStrategy]
Future<EncryptionResult> encryptWithDerivedKey({
  required EncryptionStrategy encryptionStrategy,
  DerivationStrategy keyDerivationStrategy = DerivationStrategy.pbkdf2Hmac,
  required String passphrase,
  required List<int> data,
}) async {
  assert(encryptionStrategy != EncryptionStrategy.rsa4096,
      'Asymmetric key encryption does not support derived keys');
  final derivedKey =
      await deriveNewKeyFromString(passphrase, keyDerivationStrategy);
  final result = await _encrypt(
      data: data as Uint8List, encryptionStrategy: encryptionStrategy, key: derivedKey);
  return result..derivationArtefacts = derivedKey.derivationArtefacts;
}

/// Convert encryption strategy to a service and encrypt the data
Future<EncryptionResult> _encrypt({
  required EncryptionStrategy encryptionStrategy,
  required EncryptionKey key,
  required Uint8List data,
}) {
  return encryptionStrategy.toService().encryptWithKey(data, key);
}

/// Convert encryption strategy to a service and decrypt the data
Future<List<int>> _decryptSerialized(
    String serialized, EncryptionKey key) async {
  // Should read from the first part of serialized string
  final items = serialized.split('.');
  final encryptionStrategy = encryptionStrategyFromString(items[0]);

  return await encryptionStrategy
      .toService()
      .decryptSerializedStringWithKey(serialized, key);
}
