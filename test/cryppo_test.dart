import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:cryppo/cryppo.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final serialized =
      'Pbkdf2Hmac.SzAAAAAQaQA-TgAABWl2ABQAAAAAfpc0yPy0psETSKUSYE8pw53TTyMQbAAgAAAAAA==';

  test('can derive a key', () async {
    final derivedKey =
        await deriveKeyWithSerializedOptions('Souvlaki Jay Kunde', serialized);
    expect(hex.encode(derivedKey.key.bytes),
        '5b4365749b5df9db9c1cbe28d3630168561859023d181e1774ae418a400cc50b');
  });

  test('serializes and deserializes artefacts', () async {
    DerivationArtefacts artefacts =
        DerivationArtefacts.fromSerialized(serialized);
    final reSerialized = artefacts.serialize();
    final reDerived = DerivationArtefacts.fromSerialized(reSerialized);
    final derivedKey = await deriveKeyWithSerializedOptions(
        'Souvlaki Jay Kunde', reDerived.serialize());
    expect(hex.encode(derivedKey.key.bytes),
        '5b4365749b5df9db9c1cbe28d3630168561859023d181e1774ae418a400cc50b');
  });

  test('decrypts serialised strings', () async {
    final derviedKey =
        await deriveKeyWithSerializedOptions('Souvlaki Jay Kunde', serialized);

    final decrypted = await decryptWithKey(
        key: derviedKey.key,
        encrypted:
            'Aes256Gcm.lOQl2ZU=.QUAAAAAFaXYADAAAAAAXch1m7nNZrl6peqIFYXQAEAAAAACvFVliOK4jwSAZH0JkcO8yAmFkAAUAAABub25lAAA=');

    expect(utf8.decode(decrypted), 'Hello');
  });

  test('decrypts EncryptionResult objects', () async {
    final key = DataEncryptionKey.generate(32);
    final data = utf8.encode('This is a test');

    final encrypted = await encryptWithKey(
        data: data, encryptionStrategy: EncryptionStrategy.aes256Gcm, key: key);

    final decrypted = await decryptWithKey(key: key, encrypted: encrypted);

    expect(utf8.decode(decrypted), 'This is a test');
  });

  test('encrypts', () async {
    final derivedKey =
        await deriveKeyWithSerializedOptions('Souvlaki Jay Kunde', serialized);

    final plainText = 'Hello, from Zoé';
    final bytes = utf8.encode(plainText);

    final encrypted = await encryptWithKey(
        data: bytes,
        encryptionStrategy: EncryptionStrategy.aes256Gcm,
        key: derivedKey.key);

    final decrypted = await decryptWithKey(
        key: derivedKey.key, encrypted: encrypted.serialize());

    expect(encrypted.serialize().startsWith('Aes256Gcm.'), true);
    expect(utf8.decode(decrypted), plainText);
  });
}
