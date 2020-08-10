import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:cryppo/cryppo.dart';
import 'package:cryppo/encryption/encryption_strategy.dart';
import 'package:cryppo/keys/derivation_artefacts.dart';
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

  test('decrypts', () async {
    final derviedKey =
        await deriveKeyWithSerializedOptions('Souvlaki Jay Kunde', serialized);

    final decrypted = await decryptWithKey(
        key: derviedKey.key,
        serialized:
            'Aes256Gcm.lOQl2ZU=.QUAAAAAFaXYADAAAAAAXch1m7nNZrl6peqIFYXQAEAAAAACvFVliOK4jwSAZH0JkcO8yAmFkAAUAAABub25lAAA=');

    expect(utf8.decode(decrypted), 'Hello');
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
        key: derivedKey.key, serialized: encrypted.serialize());

    expect(encrypted.serialize().startsWith('Aes256Gcm.'), true);
    expect(utf8.decode(decrypted), plainText);
  });
}
