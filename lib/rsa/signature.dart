import 'dart:convert';

/// An RSA Signature's data
class Signature {
  late List<int> signature;
  late List<int> data;
  // in bits
  late int keySize;

  Signature._(this.signature, this.data, this.keySize);

  /// Create a duplicate of the provided signature
  Signature copy() {
    return new Signature._(List<int>.from(this.signature),
        List<int>.from(this.data), this.keySize);
  }

  /// Create a [Signature] from raw signature information
  Signature.fromBytes(
      {required this.signature, required this.data, required this.keySize});

  /// Deserialize a signature encoded with [serialize] into its component parts
  Signature.fromSerializedString(String serialized) {
    if (serialized.contains('+') || serialized.contains('/')) {
      throw new Exception('string not base64 url safe encoding');
    }
    final decomposedPayload = serialized.split(".");
    if (decomposedPayload.length != 4) {
      throw Exception('Signature should contain 4 parts');
    }
    final signed = decomposedPayload[0];
    final signingStrategy = decomposedPayload[1];
    final encodedSignature = decomposedPayload[2];
    final encodedData = decomposedPayload[3];

    if (signed == 'Sign' && signingStrategy.substring(0, 3) == 'Rsa') {
      this.keySize = int.parse(signingStrategy.substring(3));
      this.signature = base64Url.decode(encodedSignature);
      this.data = base64Url.decode(encodedData);
    } else {
      throw new Exception('String is not a serialized RSA signature');
    }
  }

  /// Serialize an RSA signature into Cryppo's signature serialization format
  String serialize() {
    return 'Sign.Rsa$keySize.${base64Url.encode(signature)}.${base64Url.encode(data)}';
  }
}
