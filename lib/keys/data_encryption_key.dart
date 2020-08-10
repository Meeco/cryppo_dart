import 'dart:convert';
import 'key.dart';
import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/pointycastle.dart';

/// An encryption key intended for use in Aes/Symmetric key encryption
class DataEncryptionKey implements SymmetricKey {
  List<int> _key;

  /// The raw key
  get bytes {
    return _key;
  }

  /// The key in a format understood by the cryptography library
  SecretKey get secretKey {
    return SecretKey(_key);
  }

  // Private constructor - use a load method to be clear on incoming data
  // ignore: unused_element
  DataEncryptionKey._();

  /// Create a new random data encryption key
  DataEncryptionKey.generate(int byteLength) {
    this._key = SecureRandom().nextBytes(byteLength);
  }

  /// Convert raw key bytes into a [DataEncryptionKey]
  DataEncryptionKey.loadFromBytes(List<int> bytes) {
    assert(bytes != null && bytes.isNotEmpty);
    this._key = bytes;
  }

  /// Convert a key encoded as base64 from [serialize] into a [DataEncryptionKey]
  DataEncryptionKey.loadFromSerialized(String base64) {
    assert(base64 != null);
    _key = base64Url.decode(base64);
  }

  /// Encode a key in a human-readable and url-safe format. Can be reloaded with [DataEncryptionKey.loadFromSerialized]
  serialize() {
    return base64Url.encode(_key);
  }
}
