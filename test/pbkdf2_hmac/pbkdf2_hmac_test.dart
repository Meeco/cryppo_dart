import 'package:flutter_test/flutter_test.dart';

import '../../lib/keys/derivation_artefacts.dart';
import '../../lib/keys/derivation_strategy.dart';
import '../../lib/pbkdf2_hmac/pbkdf2_hmac.dart';

void main() {
  test('derive key with correct length', () async {
    final passphrase = 'test';
    final data1 = await Pbkdf2Hmac().deriveKey(
        artefacts: DerivationArtefacts.generate(
            strategy: DerivationStrategy.pbkdf2Hmac),
        passphrase: passphrase);
    expect(data1.length, 32);

    final data2 = await Pbkdf2Hmac().deriveKey(
        artefacts: DerivationArtefacts.generate(
            defaultLength: 48, strategy: DerivationStrategy.pbkdf2Hmac),
        passphrase: passphrase);
    expect(data2.length, 48);
  });
}
