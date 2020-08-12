import 'dart:typed_data';

import 'package:cryppo/encryption/encryption_artefacts.dart';

import '../keys/encryption_key.dart';

import 'encryption_result.dart';

/// Abstract Encryption Service to be implemented by an encryption standard (such as AES-GCM or RSA)
abstract class EncryptionService {
  /// Provided some binary data and a [EncryptionKey] (key type dependant on the encryption scheme being used)
  /// Return an [EncryptionResult]
  Future<EncryptionResult> encryptWithKey(List<int> data, EncryptionKey key);

  /// Pass a string in Cryppo serialized encrypted format and a [EncryptionKey] (key type dependant on the
  /// scheme being used) to return binary decrypted data.
  Future<Uint8List> decryptWithKey(String serialized, EncryptionKey key);

  /// Allows encryption with specified encryption artifacts (rather than generated ones).
  Future<EncryptionResult> encryptWithKeyAndArtefacts(
      List<int> data, EncryptionKey key, EncryptionArtefacts artefacts);
}
