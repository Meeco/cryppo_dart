# Cryppo Dart

Cryppo Dart is a cryptographic library that enables you to encrypt and decrypt data. Cryppo Dart combines very different ciphers under one simplified API, and a set of serialization formats.

This is a Dart port of Cryppo in [Ruby](https://github.com/Meeco/cryppo) and [JavaScript](https://github.com/Meeco/cryppo-js) used for the Meeco platform.

## Encrypt and Decrypt using a derived key

```dart
import 'package:cryppo/cryppo.dart';

Future<void> main() async {
  final encrypted = await encryptWithDerivedKey(
    data: utf8.encode('Hello World'),
    encryptionStrategy: EncryptionStrategy.aes256Gcm,
    keyDerivationStrategy: DerivationStrategy.pbkdf2Hmac,
    passphrase: 'correct horse battery staple'
  );

  print(encrypted.serialize());
  // 'Aes256Gcm.pjqdT<snip>.Pbkdf2Hmac.SzAAAA<snip>'

  // The above will include the serialized derivation artifacts but we can also get those separately:
  print(encrypted.derivationArtefacts.serialize());
  // 'Pbkdf2Hmac.SzAAAA<snip>'

  final decrypted = await decryptWithKeyDerivedFromString(
    serialized: encrypted.serialize(),
    passphrase: 'correct horse battery staple'
  );

  print(decrypted);
  // 'Hello World'
}
```

## Encrypt and Decrypt using a generated cryptographic key

```dart
import 'package:cryppo/cryppo.dart';


Future<void> main() async {
  final key = DataEncryptionKey.generate();
  print(key.serialize());
  // fB3gwp8b...
  // can be loaded later with DataEncryptionKey.loadFromSerialized('fB3gwp8b...');

  final encrypted = await encryptWithKey(
    data: utf8.encode('Hello World'),
    key: key,
    encryptionStrategy: EncryptionStrategy.aes256Gcm,
  );

  print(encrypted.serialize());
  // 'Aes256Gcm.pjqdT....'
  // Note we are not using a derived key so the above will not include derivation artifacts

  final decrypted = await decryptWithKey({
    serialized: encrypted.serialize(),
    passphrase: key
  });

  print(utf8.decode(decrypted));
  // 'Hello World'
}
```

## Signing and Verification

```dart
import 'package:cryppo/cryppo.dart';

Future<void> main() async {
  // Note, it is usually better to do this in an isolate for performance reasons.
  final keyPair = Rsa4096().generateKeyPair();

  // Alternatively, we can load from a PEM
  // final keyPair = KeyPair()..loadPrivateKeyFromPKCS1PemString(pemString);

  final signature = sign({
    keyPair.privateKey,
    data: utf8.encode('data to sign')
  });

  print(signature);
  // Sign.Rsa4096.hOQsys....

  // Alternatively, we could load the public key from a PEM also
  // final keyPair = KeyPair()..loadPublicKeyFromPKCS1PemString(pemString);
  final verified = verify({
    publicKey: keyPair.publicKey
    serializedSignature: signature
  });
  print(verified);
  // true
}
```

## Encryption Strategies

### Aes256Gcm

Aes256Gcm was chosen because it provides authenticated encryption. An error will be raised if an incorrect value, such as the encryption key, were used during decryption. This means you can always be sure that the decrypted data is the same as the data that was originally encrypted.

## Key Derivation Strategies

### Pbkdf2Hmac

Pbkdf2Hmac generates cryptographically secure keys from potentially insecure sources such as user-generated passwords.

The derived key is cryptographically secure such that brute force attacks directly on the encrypted data is infeasible. The amount of computational effort required to complete the operation can be tweaked. This ensures that brute force attacks on the password encrypted data.
