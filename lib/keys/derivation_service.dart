import 'derivation_artefacts.dart';

/// An arbitrary key derivation strategy
abstract class DerivationService {
  Future<List<int>> deriveKey(
      {String passphrase, DerivationArtefacts artefacts});
}
