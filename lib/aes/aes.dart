import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../keys/key.dart';
import '../encryption/encryption_service.dart';
import '../encryption/encryption_artefacts.dart';
import '../encryption/encryption_result.dart';
import '../encryption/encryption_strategy.dart';

// As per ruby Cryppo
const _authTagLength = 16;

// Match other cryppo implementations
const _saltBytesLength = 12;

class Aes implements EncryptionService {
  Cipher _cipher;
  EncryptionStrategy _strategy;

  @override
  Future<EncryptionResult> encryptWithKey(List<int> data, Key key) async {
    assert(key is SymmetricKey, 'AES requires a `SymmetricKey`');
    final artefacts = EncryptionArtefacts(
      authData: utf8.encode('none'),
      authTag: utf8.encode('none'),
      salt: Nonce.randomBytes(_saltBytesLength).bytes,
    );
    return encryptWithKeyAndArtefacts(data, key, artefacts);
  }

  @override
  Future<Uint8List> decryptWithKey(String serialized, Key key) {
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

  @override
  Future<EncryptionResult> encryptWithKeyAndArtefacts(
      List<int> data, Key key, EncryptionArtefacts artefacts) async {
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
}

class Aes256Gcm extends Aes {
  Cipher _cipher = aesGcm;
  EncryptionStrategy _strategy = EncryptionStrategy.aes256Gcm;
}

class Aes256Cbc extends Aes {
  Cipher _cipher = aesCbc;
  EncryptionStrategy _strategy = EncryptionStrategy.aes256Cbc;
}

class Aes256Ctr extends Aes {
  Cipher _cipher = aesCtr;
  EncryptionStrategy _strategy = EncryptionStrategy.aes256Ctr;
}
