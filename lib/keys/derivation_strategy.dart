import 'derivation_service.dart';

import '../pbkdf2_hmac/pbkdf2_hmac.dart';

enum DerivationStrategy { pbkdf2Hmac }

extension EncodeStrategy on DerivationStrategy {
  DerivationService toService() {
    switch (this) {
      case DerivationStrategy.pbkdf2Hmac:
        return Pbkdf2Hmac();
    }
    throw 'Strategy "$this" has no registered service';
  }

  String encode() {
    switch (this) {
      case DerivationStrategy.pbkdf2Hmac:
        return 'Pbkdf2Hmac';
    }
    throw 'Strategy "$this" does not have string encoding';
  }
}

DerivationStrategy derivationStrategyFromString(String strategy) {
  switch (strategy) {
    case 'Pbkdf2Hmac':
      return DerivationStrategy.pbkdf2Hmac;
  }
  throw 'Strategy "$strategy" not registered';
}
