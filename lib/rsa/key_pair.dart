import '../keys/key.dart';
import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:pointycastle/pointycastle.dart' as pointy_castle;
import 'package:basic_utils/basic_utils.dart';

/// An RSA Key pair used for encryption/decryption and signing/verification
class KeyPair implements AsymmetricKey {
  RSAPrivateKey privateKey;
  RSAPublicKey publicKey;

  KeyPair({this.publicKey, this.privateKey});

  KeyPair.generate({int keySize}) {
    final keyPair = CryptoUtils.generateRSAKeyPair(keySize: keySize);
    /**
     * Pointycastle's generation is slightly more performant and secure than Ninja's so 
     * we use it instead and then map back to Ninja keys.
     */
    final _privateKey = keyPair.privateKey as pointy_castle.RSAPrivateKey;
    final _publicKey = keyPair.publicKey as pointy_castle.RSAPublicKey;
    privateKey = RSAPrivateKey(_privateKey.n, _publicKey.e, _privateKey.d,
        _privateKey.p, _privateKey.q);
    publicKey = RSAPublicKey(_publicKey.n, _publicKey.e);
  }

  /// Encode the [privateKey] to PKCS8 pem format
  /// https://en.wikipedia.org/wiki/PKCS_8
  String encodePrivateKeyToPKCS8PemString() {
    return privateKey.toPem(toPkcs1: false);
  }

  /// Encode the [publicKey] to PKCS8 pem format
  /// https://en.wikipedia.org/wiki/PKCS_8
  String encodePublicKeyToPKCS8PemString() {
    return publicKey.toPem(toPkcs1: false);
  }

  /// Encode the [privateKey] to PKCS1 pem format
  /// https://en.wikipedia.org/wiki/PKCS_1
  String encodePrivateKeyToPKCS1PemString() {
    return privateKey.toPem(toPkcs1: true);
  }

  /// Encode the [publicKey] to PKCS1 pem format
  /// https://en.wikipedia.org/wiki/PKCS_1
  String encodePublicKeyToPKCS1PemString() {
    return publicKey.toPem(toPkcs1: true);
  }

  /// Load the [privateKey] from a PKCS1 encoded pem string
  loadPrivateKeyFromPKCS1PemString(String pem) {
    assert(
        privateKey == null, 'KeyPair already has a privateKey already loaded');
    privateKey = RSAPrivateKey.fromPEM(pem);
  }

  /// Load the [publicKey] from a PKCS1 encoded pem string
  loadPublicKeyFromPKCS1PemString(String pem) {
    assert(publicKey == null, 'KeyPair already has a publicKey already loaded');
    publicKey = RSAPublicKey.fromPEM(pem);
  }

  /// Load the [privateKey] from a PKCS8 encoded pem string
  loadPrivateKeyFromPKCS8PemString(String pem) {
    assert(
        privateKey == null, 'KeyPair already has a privateKey already loaded');
    privateKey = RSAPrivateKey.fromPEM(pem);
  }

  /// Load the [publicKey] from a PKCS8 encoded pem string
  loadPublicKeyFromPKCS8PemString(String pem) {
    assert(publicKey == null, 'KeyPair already has a publicKey already loaded');
    publicKey = RSAPublicKey.fromPEM(pem);
  }
}
