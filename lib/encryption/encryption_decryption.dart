import 'dart:typed_data';

import '../keys/data_encryption_key.dart';
import '../keys/derivation_strategy.dart';
import '../keys/derived_key.dart';
import '../keys/key.dart';
import 'encryption_result.dart';
import 'encryption_strategy.dart';

typedef DecryptionMethod = Future<Uint8List> Function(
    String serialized, DataEncryptionKey key);

/// Provided an encrypted+serialized string (in Cryppo's encryption serialization format)
/// and a [Key] (the type of which depends on the type of encryption used)
/// return the decrypted binary data.
Future<List<int>> decryptWithKey({String serialized, Key key}) async {
  return _decryptSerialized(serialized, key);
}

/// Provided an encrypted+serialized string (in Cryppo's encryption serialization format
/// which includes serialized key derivation artefacts), derive the key (using the entered
/// passphrase) and return the decrypted binary data.
Future<List<int>> decryptWithKeyDerivedFromString(
    {String serialized, String passphrase}) async {
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

/// Encrypts [data] with [key], data must be provided in bytes
/// A [key] can be a symmetrical key or a key pair, which corresponds to
/// AES or RSA [EncryptionStrategy]
Future<EncryptionResult> encryptWithKey({
  EncryptionStrategy encryptionStrategy,
  Key key,
  List<int> data,
}) {
  return _encrypt(data: data, encryptionStrategy: encryptionStrategy, key: key);
}

/// Encrypts [data] with a key derived from [passphrase]
/// using [keyDerivationStrategy], data must be provided in bytes
/// A [key] can be a symmetrical key or a key pair, which corresponds to
/// AES or RSA [EncryptionStrategy]
Future<EncryptionResult> encryptWithDerivedKey({
  EncryptionStrategy encryptionStrategy,
  DerivationStrategy keyDerivationStrategy = DerivationStrategy.pbkdf2Hmac,
  String passphrase,
  List<int> data,
}) async {
  assert(encryptionStrategy != EncryptionStrategy.rsa4096,
      'Asymmetric key encryption does not support derived keys');
  final derivedKey =
      await deriveNewKeyFromString(passphrase, keyDerivationStrategy);
  final result = await _encrypt(
      data: data, encryptionStrategy: encryptionStrategy, key: derivedKey);
  return result..derivationArtefacts = derivedKey.derivationArtefacts;
}

/// Convert encryption strategy to a service and encrypt the data
Future<EncryptionResult> _encrypt({
  EncryptionStrategy encryptionStrategy,
  Key key,
  Uint8List data,
}) {
  return encryptionStrategy.toService().encryptWithKey(data, key);
}

/// Convert encryption strategy to a service and decrypt the data
Future<List<int>> _decryptSerialized(String serialized, Key key) async {
  // Should read from the first part of serialized string
  final items = serialized.split('.');
  final encryptionStrategy = encryptionStrategyFromString(items[0]);

  return await encryptionStrategy.toService().decryptWithKey(serialized, key);
}
