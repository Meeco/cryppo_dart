import 'package:flutter_test/flutter_test.dart';

import '../../lib/keys/derivation_artefacts.dart';
import '../../lib/keys/derivation_strategy.dart';

void main() {
  test('generate a derivation artefact with correct default properties', () {
    final derivationArtefact = DerivationArtefacts.generate();
    expect(derivationArtefact.length, 32);
    expect(derivationArtefact.strategy, DerivationStrategy.pbkdf2Hmac);
    expect(derivationArtefact.salt.length, 20);
    expect(derivationArtefact.version, 'K');
    expect(derivationArtefact.iterations, greaterThanOrEqualTo(20000));
  });
}
