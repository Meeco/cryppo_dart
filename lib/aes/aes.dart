import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../keys/encryption_key.dart';
import '../encryption/encryption_service.dart';
import '../encryption/encryption_artefacts.dart';
import '../encryption/encryption_result.dart';
import '../encryption/encryption_strategy.dart';

// As per ruby Cryppo
const _authTagLength = 16;

// Match other cryppo implementations
const _saltBytesLength = 12;

/// Generic AES Encryption implementation
class Aes implements EncryptionService {
  Cipher _cipher;
  EncryptionStrategy _strategy;

  /// Provided some binary data and a [SymmetricKey] (key type dependant on the encryption scheme being used)
  /// Return an [EncryptionResult]
  @override
  Future<EncryptionResult> encryptWithKey(
      List<int> data, EncryptionKey key) async {
    assert(key is SymmetricKey, 'AES requires a `SymmetricKey`');
    final artefacts = EncryptionArtefacts(
      authData: utf8.encode('none'),
      authTag: utf8.encode('none'),
      salt: Nonce.randomBytes(_saltBytesLength).bytes,
    );
    return encryptWithKeyAndArtefacts(data, key, artefacts);
  }

  /// Pass a string in Cryppo serialized encrypted format and a [SymmetricKey] (key type dependant on the
  /// scheme being used) to return binary decrypted data.
  @override
  Future<Uint8List> decryptSerializedStringWithKey(
      String serialized, EncryptionKey key) {
    assert(key is SymmetricKey, 'AES requires a `SymmetricKey`');
    final items = serialized.split('.');
    final decodedPairs = items.sublist(1);

    final encryptedBytes = base64Url.decode(decodedPairs[0]);
    final encryptionArtefacts =
        EncryptionArtefacts.fromSerialized(decodedPairs[1]);

    // The `cryptography` library takes the last 16 bytes as the auth tag
    // so we need to concatenate them onto the cipher text.
    final fullCipher = Uint8List(encryptedBytes.length + _authTagLength);
    fullCipher.setAll(0, encryptedBytes);
    fullCipher.setAll(encryptedBytes.length, encryptionArtefacts.authTag);

    return _cipher.decrypt(fullCipher,
        aad: encryptionArtefacts.authData,
        secretKey: SecretKey((key as SymmetricKey).bytes),
        nonce: Nonce(encryptionArtefacts.salt));
  }

  /// Allows encryption with specified encryption artifacts (rather than generated ones).
  @override
  Future<EncryptionResult> encryptWithKeyAndArtefacts(
      List<int> data, EncryptionKey key, EncryptionArtefacts artefacts) async {
    final encrypted = await _cipher.encrypt(data,
        secretKey: SecretKey((key as SymmetricKey).bytes),
        nonce: artefacts.nonce,
        aad: artefacts.authData);
    final cipherText = _cipher.getDataInCipherText(encrypted);
    final authTag = _cipher.getMacInCipherText(encrypted);

    artefacts.authTag = authTag.bytes;

    return EncryptionResult(
        strategy: _strategy,
        cipherText: cipherText,
        encryptionArtefacts: artefacts);
  }

  @override
  Future<Uint8List> decryptEncryptionResultWithKey(
      EncryptionResult encryptionResult, EncryptionKey key) {
    final fullCipher = Uint8List.fromList(encryptionResult.cipherText +
        encryptionResult.encryptionArtefacts.authTag);
    return _cipher.decrypt(fullCipher,
        aad: encryptionResult.encryptionArtefacts.authData,
        secretKey: SecretKey((key as SymmetricKey).bytes),
        nonce: Nonce(encryptionResult.encryptionArtefacts.salt));
  }

  @Deprecated('use decryptSerializedStringWithKey() instead')
  @override
  Future<Uint8List> decryptWithKey(String serialized, EncryptionKey key) {
    return decryptSerializedStringWithKey(serialized, key);
  }
}

/// AES-GCM encryption with a 256-bit key.
class Aes256Gcm extends Aes {
  Cipher _cipher = aesGcm;
  EncryptionStrategy _strategy = EncryptionStrategy.aes256Gcm;
}

/// AES-CBC encryption with a 256-bit key.
class Aes256Cbc extends Aes {
  Cipher _cipher = aesCbc;
  EncryptionStrategy _strategy = EncryptionStrategy.aes256Cbc;
}

/// AES-CTR encryption with a 256-bit key.
class Aes256Ctr extends Aes {
  Cipher _cipher = aesCtr;
  EncryptionStrategy _strategy = EncryptionStrategy.aes256Ctr;
}
