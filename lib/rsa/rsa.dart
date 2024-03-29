import 'dart:convert';
import 'dart:typed_data';

import '../keys/encryption_key.dart';
import '../encryption/encryption_artefacts.dart';
import '../encryption/encryption_result.dart';
import '../encryption/encryption_strategy.dart';
import '../encryption/encryption_service.dart';
import '../rsa/signature.dart';

import 'package:ninja/ninja.dart';

import 'key_pair.dart';

class _Rsa implements EncryptionService {
  late int _keySize;
  late EncryptionStrategy _strategy;

  KeyPair generateKeyPair() {
    return KeyPair.generate(keySize: _keySize);
  }

  Future<EncryptionResult> encryptWithKey(
      List<int> data, EncryptionKey key) async {
    assert(key is KeyPair, 'RSA encryption requires a `KeyPair`');
    final KeyPair keyPair = key as KeyPair;
    assert(keyPair.publicKey != null, 'Public key is required for encryption');
    return _encryptWithPublicKey(keyPair.publicKey!, data);
  }

  Future<Uint8List> decryptSerializedStringWithKey(
      String serialized, EncryptionKey key) async {
    assert(key is KeyPair, 'RSA decryption requires a `KeyPair`');
    final KeyPair keyPair = key as KeyPair;
    assert(
        keyPair.privateKey != null, 'Private key is required for decryption');

    final items = serialized.split('.');
    final decodedPairs = items.sublist(1);
    final encryptedBytes = base64Url.decode(decodedPairs[0]);
    return _decryptWithPrivateKey(keyPair.privateKey!, encryptedBytes);
  }

  EncryptionResult _encryptWithPublicKey(
      RSAPublicKey publicKey, List<int> data) {
    final encryptedBytes =
        publicKey.encryptOaep(data, oaepPadder: sha1OaepPadder);
    return EncryptionResult.fromComponents(
      cipherText: encryptedBytes as List<int>,
      strategy: _strategy,
      encryptionArtefacts: EncryptionArtefacts.empty(),
    );
  }

  Uint8List _decryptWithPrivateKey(RSAPrivateKey privateKey, List<int> data) {
    final result = privateKey.decryptOaep(data, oaepPadder: sha1OaepPadder);
    return Uint8List.fromList(result.toList());
  }

  @override
  Future<EncryptionResult> encryptWithKeyAndArtefacts(
      List<int> data, EncryptionKey key, EncryptionArtefacts artefacts) {
    throw UnimplementedError();
  }

  @override
  Future<Uint8List> decryptEncryptionResultWithKey(
      EncryptionResult encryptionResult, EncryptionKey key) async {
    assert(key is KeyPair, 'RSA decryption requires a `KeyPair`');
    final KeyPair keyPair = key as KeyPair;
    assert(
        keyPair.privateKey != null, 'Private key is required for decryption');
    return _decryptWithPrivateKey(
        keyPair.privateKey!, encryptionResult.cipherText);
  }

  @Deprecated('use decryptSerializedStringWithKey() instead')
  @override
  Future<Uint8List> decryptWithKey(String serialized, EncryptionKey key) {
    return decryptSerializedStringWithKey(serialized, key);
  }
}

/// Sign some binary data with the provided Private Key
String sign({required RSAPrivateKey privateKey, required List<int> data}) {
  final signature = privateKey.signSsaPkcs1v15(data);

  return new Signature.fromBytes(
          signature: signature, data: data, keySize: privateKey.bitSize)
      .serialize();
}

/// Verify some signed binary data (sierlized in Cryppo's signature serliazation format)
/// with the provided Public Key
bool verify(
    {required RSAPublicKey publicKey, required String serializedSignature}) {
  final signature = Signature.fromSerializedString(serializedSignature);
  return publicKey.verifySsaPkcs1v15(signature.signature, signature.data);
}

/// RSA implementation with a 4096 bit key
class Rsa4096 extends _Rsa {
  EncryptionStrategy _strategy = EncryptionStrategy.rsa4096;
  int _keySize = 4096;
}
