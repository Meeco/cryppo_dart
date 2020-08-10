class Key {}

class AsymmetricKey extends Key {}

abstract class SymmetricKey extends Key {
  List<int> get bytes;
}
