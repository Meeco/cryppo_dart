import 'dart:typed_data';

import 'package:cryppo/encryption/encryption_artefacts.dart';

import '../keys/key.dart';

import 'encryption_result.dart';

abstract class EncryptionService {
  Future<EncryptionResult> encryptWithKey(List<int> data, Key key);

  Future<Uint8List> decryptWithKey(String serialized, Key key);

  Future<EncryptionResult> encryptWithKeyAndArtefacts(
      List<int> data, Key key, EncryptionArtefacts artefacts);
}
