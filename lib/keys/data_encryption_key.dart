import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/pointycastle.dart' as pointy_castle;

import 'encryption_key.dart';

/// An encryption key intended for use in Aes/Symmetric key encryption
class DataEncryptionKey implements SymmetricKey {
  late List<int> _key;

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
    final secureRandom = pointy_castle.SecureRandom('Fortuna'); // Get directly
    final seedSource = Random.secure();
    final seeds = <int>[];
    for (var i = 0; i < 32; i++) {
      seeds.add(seedSource.nextInt(255));
    }
    secureRandom.seed(pointy_castle.KeyParameter(Uint8List.fromList(seeds)));
    this._key = secureRandom.nextBytes(byteLength);
  }

  /// Convert raw key bytes into a [DataEncryptionKey]
  DataEncryptionKey.loadFromBytes(List<int> bytes) {
    assert(bytes.isNotEmpty);
    this._key = bytes;
  }

  /// Convert a key encoded as base64 from [serialize] into a [DataEncryptionKey]
  DataEncryptionKey.loadFromSerialized(String base64) {
    _key = base64Url.decode(base64);
  }

  /// Encode a key in a human-readable and url-safe format. Can be reloaded with [DataEncryptionKey.loadFromSerialized]
  String serialize() {
    return base64Url.encode(_key);
  }
}
