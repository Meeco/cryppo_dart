import 'dart:convert';
import 'dart:math';

import 'package:bson/bson.dart';
import 'dart:core';

import 'derivation_strategy.dart';

// Match other cryppo implementations
const _saltLength = 20;
final _random = Random.secure();

/// Derivation Artefacts from a key derivation strategy (such as Pbkdf2)
class DerivationArtefacts {
  String version;
  List<int> salt;
  int iterations;

  /// Length in bytes
  int length;
  DerivationStrategy strategy;

  DerivationArtefacts({
    this.version,
    this.salt,
    this.iterations,
    this.length,
    this.strategy,
  });

  /// Randomly generate new key derivation artefacts
  DerivationArtefacts.generate(
      {minIterations = 20000,
      defaultLength = 32,
      iterationVariance = 10,
      strategy = DerivationStrategy.pbkdf2Hmac})
      : iterations = minIterations +
            _random
                .nextInt((minIterations * (iterationVariance / 100)).floor()),
        strategy = strategy,
        length = defaultLength,
        salt = List<int>.generate(_saltLength, (i) => _random.nextInt(256)),
        version = 'K';

  /// Serialize the artefacts in Cryppo's artefact serialization format ([serialize]) to be appended onto a serialized encrypted string
  DerivationArtefacts.fromSerialized(String serialized) {
    final parts = serialized.split('.');
    strategy = derivationStrategyFromString(parts[0]);
    final artefacts = parts[1];
    final bsonData = base64Url.decode(artefacts);
    version = utf8.decode(bsonData.sublist(0, 1));
    final bsonBuffer = bsonData.sublist(1);
    final deserialized = BSON().deserialize(BsonBinary.from(bsonBuffer));
    final BsonBinary iv = deserialized['iv'];

    iterations = deserialized['i'];
    salt = iv.byteList;
    length = deserialized['l'];
  }

  /// Convert arteacts into Cryppo's artefact serialization format. Can be reloaded with [DerivationArtefacts.fromSerialized]
  String serialize() {
    final artefactPayload = BSON()
        .serialize({'i': iterations, 'iv': BsonBinary.from(salt), 'l': length});
    final serializedArtefacts = base64Url
        .encode([...utf8.encode(version), ...artefactPayload.byteList]);
    return '${strategy.encode()}.$serializedArtefacts';
  }

  /// Serializes the artifacts with [serialize]
  @override
  String toString() {
    return serialize();
  }
}
