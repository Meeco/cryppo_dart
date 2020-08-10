import 'dart:convert';
import 'key.dart';
import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/pointycastle.dart';

class DataEncryptionKey implements SymmetricKey {
  List<int> _key;

  get bytes {
    return _key;
  }

  SecretKey get secretKey {
    return SecretKey(_key);
  }

  // Private constructor - use a load method to be clear on incoming data
  // ignore: unused_element
  DataEncryptionKey._();

  DataEncryptionKey.generate(int byteLength) {
    this._key = SecureRandom().nextBytes(byteLength);
  }

  DataEncryptionKey.loadFromBytes(List<int> bytes) {
    assert(bytes != null && bytes.isNotEmpty);
    this._key = bytes;
  }

  DataEncryptionKey.loadFromSerialized(String base64) {
    assert(base64 != null);
    _key = base64Url.decode(base64);
  }

  serialize() {
    return base64Url.encode(_key);
  }
}
