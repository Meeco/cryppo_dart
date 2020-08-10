class EncryptionKey {}

class AsymmetricKey extends EncryptionKey {}

abstract class SymmetricKey extends EncryptionKey {
  List<int> get bytes;
}
