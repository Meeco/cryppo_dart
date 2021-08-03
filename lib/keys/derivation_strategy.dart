import 'derivation_service.dart';

import '../pbkdf2_hmac/pbkdf2_hmac.dart';

/// Strategy used to derive a fixed-length encryption key
enum DerivationStrategy { pbkdf2Hmac }

/// Convert a [DerivationStrategy] to its corresponding [DerivationService] implementation
extension EncodeStrategy on DerivationStrategy {
  DerivationService toService() {
    switch (this) {
      case DerivationStrategy.pbkdf2Hmac:
        return Pbkdf2Hmac();
    }
  }

  /// Serialize a [DerivationStrategy] into a string to be used in Cryppo's serialization format
  String encode() {
    switch (this) {
      case DerivationStrategy.pbkdf2Hmac:
        return 'Pbkdf2Hmac';
    }
  }
}

/// Maps a serialized [DerivationStrategy] string into the actual enum value
DerivationStrategy derivationStrategyFromString(String strategy) {
  switch (strategy) {
    case 'Pbkdf2Hmac':
      return DerivationStrategy.pbkdf2Hmac;
  }
  throw 'Strategy "$strategy" not registered';
}
