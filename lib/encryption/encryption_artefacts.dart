import 'dart:convert';

import 'package:bson/bson.dart';

/// Storage for artifacts generated during encrypted (or provided in `encryptWithKeyAndArtefacts`)
class EncryptionArtefacts {
  late List<int> salt;
  late List<int> authTag;
  late List<int> authData;
  late String version;

  /// The salt in a format understood by the cryptography library
  List<int> get nonce {
    return salt;
  }

  EncryptionArtefacts.empty() {
    this.authData = [];
    this.salt = [];
    this.authTag = [];
    this.version = 'A';
  }

  /// Storage for artifacts generated during encrypted (or provided in `encryptWithKeyAndArtefacts`)
  EncryptionArtefacts(
      {required this.salt, required this.authTag, required this.authData}) {
    // WARNING: Should we put a default version here if no version is supplied?
    version = 'A';
  }

  /// Create new encryption artefacts from Cryppo's artifact serialized/encrypted format
  /// (this is the third part of the serialized string)
  EncryptionArtefacts.fromSerialized(String serialized) {
    final artefactBytes = base64Url.decode(serialized);
    final versionByte = artefactBytes.sublist(0, 1);
    this.version = utf8.decode(versionByte);
    final decoded =
        BSON().deserialize(BsonBinary.from(artefactBytes.sublist(1)));
    this.salt = decoded['iv'].byteList;
    this.authTag = decoded['at'].byteList;
    this.authData = utf8.encode(decoded['ad']);
  }

  /// Convert artefacts to a format that can be used in Cryppo's encryption serialization format
  String serialize() {
    final versionByte = utf8.encode('A');
    final bsonPayload = BSON().serialize({
      'iv': BsonBinary.from(salt),
      'at': BsonBinary.from(authTag),
      'ad': utf8.decode(authData)
    });

    return base64Url.encode([...versionByte, ...bsonPayload.byteList]);
  }

  /// Serializes the artefacts
  @override
  String toString() {
    return serialize();
  }
}
