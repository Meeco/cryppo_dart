import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryppo/cryppo.dart';
import 'package:cryppo/encryption/encryption_result.dart';
import 'package:cryppo/encryption/encryption_strategy.dart';
import 'package:cryppo/keys/derivation_artefacts.dart';
import 'package:flutter_test/flutter_test.dart';

const _bufferSize = 1024; //in bytes

main() async {
  final derivationArtefacts = DerivationArtefacts.generate();
  final key = await deriveKeyWithSerializedOptions(
      "passphrase", derivationArtefacts.serialize());
  final fileDescriptor = File('./test/compat.json');
  final file = await fileDescriptor.open();

  // keep track of the number of chunks this file was devided into
  int numChunks = 0;

  // List of serialised encrypted chunks of the file
  final serialisedEncryptedChunks = <String>[];
  test(
    'can encrypt a file in chunks',
    () async {
      final expectedNumChunks = (await file.length() / _bufferSize).ceil();

      // buffer for reading this file, once the buffer is full, then buffer contents will then undergo encryption
      Uint8List buffer = Uint8List(_bufferSize);

      // keep reading the file into buffer until it reaches EOF
      while (true) {
        final nBytesRead = await file.readInto(buffer);
        // encrypts this chunk, then add it to results for further processing
        EncryptionResult encryptionResult = await encryptWithKey(
          // nBytesRead may be smaller than buffer size (i.e. last chunk), do not encrypt junk data
          data: buffer.sublist(0, nBytesRead),
          encryptionStrategy: EncryptionStrategy.aes256Gcm,
          key: key,
        );
        serialisedEncryptedChunks.add(encryptionResult.serialize());

        if (nBytesRead == 0) {
          // file reader reaches EOF, close file descriptor
          await file.close();
          break;
        }
        numChunks++;
      }

      expect(numChunks, expectedNumChunks);

      var encryptionResults = serialisedEncryptedChunks
          .map((e) => EncryptionResult.fromSerialized(e))
          .toList();

      for (var val in encryptionResults) {
        // Note: Synchronised chunking test only! If chunking and encryption were done asynchronously (in parallel), then skip this test
        expect(val.serialize(),
            serialisedEncryptedChunks[encryptionResults.indexOf(val)],
            reason:
                'serialised data before and after encryption must match, also match maintain ordinality after sorting');
      }
    },
  );

  test(
    'decrypts file chunks, and reassembles into a single file',
    () async {
      // decrypt and combine each chunk into a single file
      List<int> decryptedFileData = (await Future.wait(serialisedEncryptedChunks
              .map((e) => decryptWithKey(encrypted: e, key: key))))
          .reduce((v, e) => v + e);
      final fileData = fileDescriptor.readAsBytesSync();
      expect(decryptedFileData, fileData,
          reason: 're-assembled file must match original file');
    },
  );
}
