import 'dart:convert';

import 'package:bson/bson.dart';
import 'package:cryptography/cryptography.dart';

class EncryptionArtefacts {
  List<int> salt;
  List<int> authTag;
  List<int> authData;
  String version;

  Nonce get nonce {
    return Nonce(salt);
  }

  EncryptionArtefacts({List<int> salt, List<int> authTag, List<int> authData}) {
    this.salt = salt ?? [];
    this.authTag = authTag ?? [];
    this.authData = authData ?? [];
    // WARNING: Should we put a default version here if no version is supplied?
    version = 'A';
  }

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

  serialize() {
    final versionByte = utf8.encode('A');
    final bsonPayload = BSON().serialize({
      'iv': BsonBinary.from(salt),
      'at': BsonBinary.from(authTag),
      'ad': utf8.decode(authData)
    });

    return base64Url.encode([...versionByte, ...bsonPayload.byteList]);
  }

  @override
  String toString() {
    return serialize();
  }
}
