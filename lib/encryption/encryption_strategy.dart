import 'encryption_service.dart';

import '../aes/aes.dart';
import '../rsa/rsa.dart';

/// Encryption strategy. Preference should be `EncryptionStrategy.aes256Gcm` for symmetric encryption and
/// `EncryptionStrategy.rsa4096` for asymmetric encryption.
enum EncryptionStrategy {
  /// (Recommended for symmetric encryption) https://en.wikipedia.org/wiki/Galois/Counter_Mode
  aes256Gcm,

  /// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
  aes256Cbc,

  /// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
  aes256Ctr,

  /// For asymmetric encryption
  /// https://en.wikipedia.org/wiki/RSA_(cryptosystem)
  rsa4096,
}

/// Convert an [EncryptionStrategy] into its respective [EncryptionService].
extension MapToService on EncryptionStrategy {
  EncryptionService toService() {
    switch (this) {
      case EncryptionStrategy.aes256Gcm:
        return Aes256Gcm();
      case EncryptionStrategy.aes256Cbc:
        return Aes256Cbc();
      case EncryptionStrategy.aes256Ctr:
        return Aes256Ctr();
      case EncryptionStrategy.rsa4096:
        return Rsa4096();
    }
  }

  /// Convert an [EncryptionStrategy] to a string so it can be used in Cryppo's serialization format
  String encode() {
    switch (this) {
      case EncryptionStrategy.aes256Gcm:
        return 'Aes256Gcm';
      case EncryptionStrategy.aes256Cbc:
        return 'Aes256Cbc';
      case EncryptionStrategy.aes256Ctr:
        return 'Aes256Ctr';
      case EncryptionStrategy.rsa4096:
        return 'Rsa4096';
    }
  }
}

/// Given a string from Cryppo's seralization format, return the corresponding [EncryptionStrategy]
EncryptionStrategy encryptionStrategyFromString(String strategy) {
  switch (strategy) {
    case 'Aes256Gcm':
      return EncryptionStrategy.aes256Gcm;
    case 'Aes256Cbc':
      return EncryptionStrategy.aes256Cbc;
    case 'Aes256Ctr':
      return EncryptionStrategy.aes256Ctr;
    case 'Rsa4096':
      return EncryptionStrategy.rsa4096;
  }
  throw 'Strategy "$strategy" not registered';
}
