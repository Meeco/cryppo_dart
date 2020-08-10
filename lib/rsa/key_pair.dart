import '../keys/key.dart';
import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:pointycastle/pointycastle.dart' as pointy_castle;
import 'package:basic_utils/basic_utils.dart';

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

  String encodePrivateKeyToPKCS8PemString() {
    return privateKey.toPem(toPkcs1: false);
  }

  String encodePublicKeyToPKCS8PemString() {
    return publicKey.toPem(toPkcs1: false);
  }

  String encodePrivateKeyToPKCS1PemString() {
    return privateKey.toPem(toPkcs1: true);
  }

  String encodePublicKeyToPKCS1PemString() {
    return publicKey.toPem(toPkcs1: true);
  }

  loadPrivateKeyFromPKCS1PemString(String pem) {
    assert(
        privateKey == null, 'KeyPair already has a privateKey already loaded');
    privateKey = RSAPrivateKey.fromPEM(pem);
  }

  loadPublicKeyFromPKCS1PemString(String pem) {
    assert(publicKey == null, 'KeyPair already has a publicKey already loaded');
    publicKey = RSAPublicKey.fromPEM(pem);
  }

  loadPrivateKeyFromPKCS8PemString(String pem) {
    assert(
        privateKey == null, 'KeyPair already has a privateKey already loaded');
    privateKey = RSAPrivateKey.fromPEM(pem);
  }

  loadPublicKeyFromPKCS8PemString(String pem) {
    assert(publicKey == null, 'KeyPair already has a publicKey already loaded');
    publicKey = RSAPublicKey.fromPEM(pem);
  }
}
