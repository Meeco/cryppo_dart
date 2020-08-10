/// An arbitrary encryption key
abstract class Key {}

/// An arbitrary asymmetric (public/private) encryption key such as those used in RSA
abstract class AsymmetricKey extends Key {}

/// An arbitrary symmetric encryption key such as those used in AES
abstract class SymmetricKey extends Key {
  List<int> get bytes;
}
