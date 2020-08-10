import 'dart:convert';

class Signature {
  List<int> signature;
  List<int> data;
  // in bits
  int keySize;

  Signature._(this.signature, this.data, this.keySize);

  Signature copy() {
    return new Signature._(List<int>.from(this.signature),
        List<int>.from(this.data), this.keySize);
  }

  Signature.fromBytes({this.signature, this.data, this.keySize});

  Signature.fromSerializedString(String serialized) {
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
      this.signature = base64.decode(encodedSignature);
      this.data = base64.decode(encodedData);
    } else {
      throw new Exception('String is not a serialized RSA signature');
    }
  }

  String serialize() {
    return 'Sign.Rsa$keySize.${base64.encode(signature)}.${base64.encode(data)}';
  }
}
