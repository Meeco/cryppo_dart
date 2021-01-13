import 'dart:convert';
import 'dart:typed_data';

import 'package:cryppo/cryppo.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> main() async {
  final longString =
      'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.';
  final rsa = Rsa4096();
  final keyPair = rsa.generateKeyPair();

  test('can encrypt and decrypt', () async {
    final bytes = utf8.encode(longString);
    final encryptionResult = await encryptWithKey(
        data: bytes,
        key: keyPair,
        encryptionStrategy: EncryptionStrategy.rsa4096);
    expect(encryptionResult.serialize().startsWith('Rsa4096.'), true);
    final decryptedBytes =
        await rsa.decryptEncryptionResultWithKey(encryptionResult, keyPair);
    final decryptedString = utf8.decode(decryptedBytes);
    expect(longString, decryptedString,
        reason: "string must match after encryption and decryption");
  });

  test('can sign and verify', () async {
    final bytes = utf8.encode(longString);
    final signature = sign(privateKey: keyPair.privateKey, data: bytes);
    expect(signature.startsWith('Sign.Rsa4096.'), true);
    final verificationResult =
        verify(publicKey: keyPair.publicKey, serializedSignature: signature);
    expect(true, verificationResult,
        reason: "signature must match original data");
    final newSignature = Signature.fromSerializedString(signature);
    final tamperedSignature = tamperWithData(newSignature);
    expect(
        false,
        verify(
            publicKey: keyPair.publicKey,
            serializedSignature: tamperedSignature.serialize()),
        reason: "tempered data must not match signature");
  });

  test('can output to pem format and load from PKCS#8 pem string', () {
    // final keyPair = generateRSAKeyPair();
    String publicKeyPem = keyPair.encodePublicKeyToPKCS8PemString();
    String privateKeyPem = keyPair.encodePrivateKeyToPKCS8PemString();
    KeyPair pair = KeyPair()
      ..loadPublicKeyFromPKCS8PemString(publicKeyPem)
      ..loadPrivateKeyFromPKCS8PemString(privateKeyPem);

    final publicKey = pair.publicKey;
    final privateKey = pair.privateKey;

    // Ninja RSA key pairs do not have equality overload
    expect(keyPair.publicKey.e, publicKey.e);
    expect(keyPair.publicKey.n, publicKey.n);
    expect(keyPair.publicKey.bitSize, publicKey.bitSize);
    expect(keyPair.publicKey.blockSize, publicKey.blockSize);

    // Ninja RSA key pairs do not have equality overload
    expect(keyPair.privateKey.d, privateKey.d);
    expect(keyPair.privateKey.p, privateKey.p);
    expect(keyPair.privateKey.q, privateKey.q);
    expect(keyPair.privateKey.e, privateKey.e);
    expect(keyPair.privateKey.n, privateKey.n);
    expect(keyPair.privateKey.bitSize, privateKey.bitSize);
    expect(keyPair.privateKey.blockSize, privateKey.blockSize);
  });

  test('can output to pem format and load from PKCS#1 pem string', () {
    String publicKeyPem = keyPair.encodePublicKeyToPKCS1PemString();
    String privateKeyPem = keyPair.encodePrivateKeyToPKCS1PemString();
    KeyPair pair = KeyPair()
      ..loadPublicKeyFromPKCS1PemString(publicKeyPem)
      ..loadPrivateKeyFromPKCS1PemString(privateKeyPem);

    final publicKey = pair.publicKey;
    final privateKey = pair.privateKey;

    expect(keyPair.publicKey.e, publicKey.e);
    expect(keyPair.publicKey.n, publicKey.n);
    expect(keyPair.publicKey.bitSize, publicKey.bitSize);
    expect(keyPair.publicKey.blockSize, publicKey.blockSize);

    expect(keyPair.privateKey.d, privateKey.d);
    expect(keyPair.privateKey.p, privateKey.p);
    expect(keyPair.privateKey.q, privateKey.q);
    expect(keyPair.privateKey.e, privateKey.e);
    expect(keyPair.privateKey.n, privateKey.n);
    expect(keyPair.privateKey.bitSize, privateKey.bitSize);
    expect(keyPair.privateKey.blockSize, privateKey.blockSize);
  });

  test(
      'can load PKCS#1 private key string literal and assign each part correctly',
      () {
    final pair = KeyPair()..loadPrivateKeyFromPKCS1PemString(PRIVATE_KEY_PEM);
    final privateKey = pair.privateKey;
    expect(expectedPublicExponent, privateKey.e,
        reason: 'public exponent must match');
    expect(expectedPrivateExponent, privateKey.d,
        reason: 'private exponent must match');
    expect(expectedModulus, privateKey.n, reason: 'modulus must match');
    expect(expectedP, privateKey.p, reason: 'p must match');
    expect(expectedQ, privateKey.q, reason: 'q must match');
  });

  test(
      'can load PKCS#1 public key string literal and assign each part correctly',
      () {
    final pair = KeyPair()..loadPublicKeyFromPKCS1PemString(PUBLIC_KEY_PEM);
    final publicKey = pair.publicKey;
    expect(expectedPublicExponent, publicKey.e,
        reason: 'public exponent must match');
    expect(expectedModulus, publicKey.n, reason: 'modulus must match');
  });
}

Signature tamperWithData(Signature sigature) {
  Signature sigCopy = sigature.copy();
  final dataCopy = Uint8List.fromList(sigature.data);
  dataCopy[dataCopy.length - 1] ^= 1; // xor last bit
  sigCopy.data = dataCopy;
  return sigCopy;
}

final expectedModulus = BigInt.parse(
    '2736307442096091061479976827609422395069467298735352347857561704'
    '8292187044756879516071751152302761045592672634380454645179579389'
    '1247384586211304287995108001875066199715083334074435967556687399'
    '9319251479798914660139787259708209806761757009712728724790482405'
    '7651253377088098786414563575337058691687308109208896589867638426'
    '3597756332186955927783414432681703994818829934909865953936807204'
    '5089374673421283131773432601260236087842470456477527284269529920'
    '9236346457027022908172067250756592121219157754099664357704607422'
    '3041635653669245371585889101126586702622629740303379451510725987'
    '88797008033612889633467715945087208346497');

final expectedPrivateExponent = BigInt.parse(
    '2012994044673678049760198403795307718288664828630049327055810038'
    '2216323816910499902472913595464745384914773726618320335200620429'
    '4958727940781628906375149031759198112316146799300101947049919428'
    '9167631591246854029163977038196925697139090753456517539837397626'
    '2134975343234333380981817197273686783073991575282489514518778654'
    '0764374481577527357344634545283763678563461581907950912955299734'
    '7232049164384490158450113676636604834650297037761692726902235748'
    '3252673984385902383489131299035550079282377607128917226237346480'
    '4757648317210338130231521085366318380215406736622417638534538031'
    '30986837268331781597679044932297479458497');

final expectedP = BigInt.parse(
    '1746818282918629043887570109341783600524931564831424027772183448'
    '1777918484839763741768663354054850249145952922091155437389551311'
    '0186823754121009665820646073047300961788964532376600780354538537'
    '0868715825197050747098270955502374883585770390213253010823493222'
    '04921888825444491698321155427032670343468855826116329');

final expectedQ = BigInt.parse(
    '1566452257142739545821524601539678379560286550085718375022878215'
    '4451895840557211082760890790929238013479870540283197382620702416'
    '5384805271627128418862280626618037695428297092711952308471296803'
    '3694803404338678296562263369203809906281297904997776540052229579'
    '86559762623534181808705370992757247052692604976255193');
final expectedPublicExponent = BigInt.from(65537);

const PRIVATE_KEY_PEM = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitMnb08XcLe
9sUaPLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxGBzOMCUJ5
Fmb3Mmc+/Yndh96++aMPhC+kheM8a0pyfQMdPXCjdqDN50FJ9I5GqhuB2/7YWymx
fEs3rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwbbu28D7j9V4YqWTgXAgZ13a1gmZOq
X2LQP2quRJ+2tiQMoJSKRLACG7UlZo+tgYLLZkjsv+LUI1Yp4eiBvMvIsaufRm5g
vCj/c1EN4YS30/56q3l6XodN/XKLVE1iR8lTgQIDAQABAoIBAQCfdbhaGsf+o/rp
PcIqVFn5JfmDwcjvjlRKWFbBpCsAHFgNji/jEMulfeYCz1xSr101fFlSSblPWqvj
tbuE6r2qw1IUzHt862aVg5q9wC9gWt6ZbUqRXXxbmzLu6H6N1yNdmUTv9PCvAqXP
NHyXVTQsn/HRcqkniJN0kzqPKB9XjH/Yc64fERei+hJS63EB6OFsepaICmuEQjsl
6YV9ELT8cDIqxdue/22adQfho60OzHZHC8LO/Uu0YLy2huSbdFJGauxP+jTON5Ll
AI7UBWoiYi5iF2/wN1t/8G9IA2DeRD6wa+cM7+j49e02peSXXlVuL9u9BEoD6x3M
C+IIkI7BAoGBAPjBU4QOO+PwlQRY2qOv+5fi6kVsFFT35jYO6UG0X/DJRjXN3pF4
Hd8LY1JVcTX9SVbXGrkd/H+WVQy/Abth+3psZ9RkBapLuJcFSjiFzNh9Fj5NswXK
jTEX2Uuk60LC2T5M1Sb8R1YzAGktlKQOcmPT7LjmGpgFnAhmAPD1pO7pAoGBAN8R
+QRjAPiYlOqGYxDm+Bv0DwNsQ5xDCOHph7znyYNZ8lttxStprye5TuLJoTrfSJjJ
SN+yh3MeCQD6x4DiMftA8uubkmhgbnoKXSfGrkaCUG2R3wB0+9HYih2LN7tCxMfd
PGRw4gcqdIlYCSS1XQpYZ+PxLegbcHLTUOhiglDZAoGBALE566qWCY1ohoLGW19r
rjCUdpxnWEUBKX8yOHWbcQ84F1GWDxBNJ9sVXfn27eWtQ2cfceaZup+cF5QxMaaz
NFwQiBkF+hNOR4ExP6Ptj/hdhk91RCrIGLf1adc+9G5oLCb6zpIsAxci1xQYaWJI
+K6u+mTxa9kLhhNluR3zpUKhAoGBAI1qLG6OgRAYUte26FjPw9ycxWPLH7WRfbES
Rj4Ix2RhAlbZ6RRThHnvbUYywua6pKBPgsZlvJ7LHLQlR5K6UytQim+5CYDoGUF/
Dn1n5BXJCUndHv2ALCBlYXHHT0aE1pFJ/L5EHdajIIvtZqaB34DueLY1sH+j3Y69
zl30DV9JAoGAZxjGv1i//HdMIXeUmVXuz0muqMHShUxaweGPzuyGTIp99pwyycqg
Xk1lHr+gJVgqNV0Ox2YD1H5RPz8dknqAavp2RNyZopR1Pyk8KDMrIDXweCjuNFVL
RIAnxB5ixrTrBtx02R5xCHJiCcELLyX0aZZlSSVUPHVPXqvAdU8LgAU=
-----END RSA PRIVATE KEY-----''';

const PUBLIC_KEY_PEM = '''-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitMnb08XcLe9sUa
PLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxGBzOMCUJ5Fmb3
Mmc+/Yndh96++aMPhC+kheM8a0pyfQMdPXCjdqDN50FJ9I5GqhuB2/7YWymxfEs3
rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwbbu28D7j9V4YqWTgXAgZ13a1gmZOqX2LQ
P2quRJ+2tiQMoJSKRLACG7UlZo+tgYLLZkjsv+LUI1Yp4eiBvMvIsaufRm5gvCj/
c1EN4YS30/56q3l6XodN/XKLVE1iR8lTgQIDAQAB
-----END RSA PUBLIC KEY-----
''';
