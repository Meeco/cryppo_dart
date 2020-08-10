import 'encryption_service.dart';

import '../aes/aes.dart';
import '../rsa/rsa.dart';

enum EncryptionStrategy {
  aes256Gcm,
  aes256Cbc,
  aes256Ctr,
  rsa4096,
}

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
    throw 'Encryption strategy has no service';
  }

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
    throw 'Strategy "$this" does not have string encoding';
  }
}

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
