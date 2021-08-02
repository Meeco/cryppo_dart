import 'dart:convert';
import 'dart:io';

import 'package:cryppo/cryppo.dart';
import 'package:cryppo/keys/data_encryption_key.dart';
import 'package:cryppo/rsa/key_pair.dart';
import 'package:cryppo/rsa/rsa.dart';
import 'package:cryppo/rsa/signature.dart';
import 'package:flutter_test/flutter_test.dart';

void main() async {
  final tests = await new File('./test/compat.json').readAsString();
  final Map<String, dynamic> testData = json.decode(tests);
  final List<dynamic> derivedKeyTestCases =
      testData['encryption_with_derived_key'];
  final List<dynamic> providedKeyTestCases = testData['encryption_with_key'];
  final List<dynamic> signatureTestCases = testData['signatures'];

  group('Compatibility', () {
    providedKeyTestCases
        // At this stage the Dart version does not support the legacy format
        .where((element) => element['encryption_strategy'] == 'Aes256Gcm')
        // At this stage the Dart version does not support the legacy format
        .where((element) => element['format'] == 'latest_version')
        .forEach((testCase) {
      final index = providedKeyTestCases.indexOf(testCase);
      test('Passes provided key compatibility test $index', () async {
        final key = DataEncryptionKey.loadFromSerialized(testCase['key']);
        final decrypted =
            await decryptWithKey(key: key, encrypted: testCase['serialized']);
        expect(utf8.decode(decrypted), testCase['expected_decryption_result']);
      });
    });

    derivedKeyTestCases
        // At this stage the Dart version does not support the legacy format
        .where((element) => element['format'] == 'latest_version')
        .forEach((testCase) {
      final index = derivedKeyTestCases.indexOf(testCase);
      test('Passes derived key compatibility test $index', () async {
        final decrypted = await decryptWithKeyDerivedFromString(
            passphrase: testCase['passphrase'],
            serialized: testCase['serialized']);
        expect(utf8.decode(decrypted), testCase['expected_decryption_result']);
      });
    });

    signatureTestCases.forEach((testCase) {
      final index = signatureTestCases.indexOf(testCase);
      test('Passes compatibility test $index', () async {
        final signature =
            Signature.fromSerializedString(testCase['serialized_signature']);
        final keyPair = KeyPair()
          ..loadPublicKeyFromPKCS1PemString(testCase['public_pem']);
        final result = verify(
            publicKey: keyPair.publicKey,
            serializedSignature: signature.serialize());
        expect(result, true,
            reason: "public key should verify authentic signature");
      });
    });

    providedKeyTestCases
        // At this stage the Dart version does not support the legacy format
        .where((element) => element['encryption_strategy'] == 'Rsa4096')
        // At this stage the Dart version does not support the legacy format
        .where((element) => element['format'] == 'latest_version')
        .forEach((testCase) {
      final index = providedKeyTestCases.indexOf(testCase);
      test('Passes provided key compatibility test $index', () async {
        final privateKey = KeyPair()
          ..loadPrivateKeyFromPKCS1PemString(testCase['key']);
        final decrypted = await decryptWithKey(
            encrypted: testCase['serialized'], key: privateKey);
        expect(utf8.decode(decrypted), testCase['expected_decryption_result']);
      });
    });
  });
}
