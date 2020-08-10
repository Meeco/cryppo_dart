import 'derivation_artefacts.dart';

abstract class DerivationService {
  Future<List<int>> deriveKey(
      {String passphrase, DerivationArtefacts artefacts});
}
