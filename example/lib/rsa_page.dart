import 'dart:convert';
import 'dart:ui';

import 'package:cryppo/cryppo.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

class RsaPage extends StatefulWidget {
  @override
  _RsaPageState createState() => _RsaPageState();
}

KeyPair computeRSAKeys(int keySize) {
  return KeyPair.generate(keySize: keySize);
}

class _RsaPageState extends State<RsaPage> {
  KeyPair? keyPair;
  bool isGenerateRsaKeyButtonEnabled = true;
  String generateRsaKeyButtonText = 'Generate RSA Pair';

  final privateKeyEditingController = TextEditingController();
  final publicKeyEditingController = TextEditingController();
  final textToEncryptEditingController = TextEditingController();
  final serialisedCipherTextEditingController = TextEditingController();
  final plainTextEditingController = TextEditingController();
  final rsaSignatureEditingController = TextEditingController();
  final rsaVerifyEditingController = TextEditingController();

  void _showDialog(String title, String content) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (_) => AlertDialog(
        title: Text(title),
        content: Text(content),
        actions: <Widget>[
          FlatButton(
            child: Text("OK"),
            onPressed: () {
              Navigator.of(context).pop();
            },
          )
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: ListView(
        children: <Widget>[
          Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: <Widget>[
              Expanded(
                child: RaisedButton(
                  child: Text('$generateRsaKeyButtonText'),
                  onPressed: isGenerateRsaKeyButtonEnabled
                      ? () async {
                          setState(() {
                            isGenerateRsaKeyButtonEnabled = false;
                            generateRsaKeyButtonText = 'Please wait...';
                            privateKeyEditingController.text = '';
                            publicKeyEditingController.text = '';
                          });
                          final newPair = await compute(computeRSAKeys, 4096);

                          setState(() {
                            isGenerateRsaKeyButtonEnabled = true;
                            generateRsaKeyButtonText = 'Generate RSA Key Pair';
                            keyPair = newPair;
                            privateKeyEditingController.text =
                                keyPair!.encodePrivateKeyToPKCS1PemString();
                            publicKeyEditingController.text =
                                keyPair!.encodePublicKeyToPKCS1PemString();
                          });
                        }
                      : null,
                ),
              ),
              SizedBox(width: 5),
              Expanded(
                child: RaisedButton(
                  child: Text('Load from PKCS#1 PEM'),
                  onPressed: () {
                    if (privateKeyEditingController.text == null ||
                        publicKeyEditingController == null) {
                      _showDialog(
                          'Missing Data', 'Missing private key/public key');
                    }
                    _reloadKeyPair();
                  },
                ),
              ),
            ],
          ),
          SizedBox(height: 5),
          TextField(
            minLines: 1,
            maxLines: null,
            style: TextStyle(
              fontSize: 9,
              fontWeight: FontWeight.w400,
              fontFeatures: [
                FontFeature.tabularFigures(),
              ],
            ),
            controller: privateKeyEditingController,
            decoration: InputDecoration(
              border: OutlineInputBorder(),
              labelText: 'Private Key',
            ),
          ),
          SizedBox(height: 5),
          TextField(
            minLines: 1,
            maxLines: null,
            style: TextStyle(
              fontSize: 9,
              fontWeight: FontWeight.w400,
              fontFeatures: [
                FontFeature.tabularFigures(),
              ],
            ),
            controller: publicKeyEditingController,
            decoration: InputDecoration(
              border: OutlineInputBorder(),
              labelText: 'Public Key',
            ),
          ),
          SizedBox(height: 5),
          TextField(
            minLines: 1,
            maxLines: null,
            controller: textToEncryptEditingController,
            decoration: InputDecoration(
              border: OutlineInputBorder(),
              labelText: 'Text to Encrypt',
            ),
          ),
          SizedBox(height: 5),
          RaisedButton(
            child: Text('Encrypt with Public Key'),
            onPressed: () async {
              _reloadKeyPair();
              if (keyPair?.publicKey == null) {
                return;
              }
              if (textToEncryptEditingController.text.isEmpty) {
                _showDialog(
                    'Missing Data', 'Missing public key or text to encrypt');
                return;
              }
              final encryptionResult = await encryptWithKey(
                  data: utf8.encode(textToEncryptEditingController.text),
                  key: keyPair!,
                  encryptionStrategy: EncryptionStrategy.rsa4096);
              setState(() {
                serialisedCipherTextEditingController.text =
                    encryptionResult.serialize();
              });
            },
          ),
          SizedBox(height: 5),
          TextField(
            minLines: 1,
            maxLines: null,
            style: TextStyle(
              fontSize: 9,
              fontWeight: FontWeight.w400,
              fontFeatures: [
                FontFeature.tabularFigures(),
              ],
            ),
            controller: serialisedCipherTextEditingController,
            decoration: InputDecoration(
              border: OutlineInputBorder(),
              labelText: 'Serialised Cipher Text',
            ),
          ),
          SizedBox(height: 5),
          RaisedButton(
            child: Text('Decrypt with Private Key'),
            onPressed: () async {
              _reloadKeyPair();
              if (keyPair?.privateKey == null) {
                return;
              }
              if (serialisedCipherTextEditingController.text.isEmpty) {
                _showDialog('Missing Data',
                    'Missing private key or serialised cipher text');
                return;
              }
              try {
                final decryptedText = await decryptWithKey(
                    key: keyPair!,
                    encrypted: serialisedCipherTextEditingController.text);
                setState(() {
                  plainTextEditingController.text = utf8.decode(decryptedText);
                });
              } catch (e) {
                _showDialog('Failed', '$e');
              }
            },
          ),
          SizedBox(height: 5),
          TextField(
            maxLines: 1,
            controller: plainTextEditingController,
            decoration: InputDecoration(
              border: OutlineInputBorder(),
              labelText: 'Plain Text',
            ),
          ),
          SizedBox(height: 5),
          TextField(
            minLines: 1,
            maxLines: null,
            style: TextStyle(
              fontSize: 9,
              fontWeight: FontWeight.w400,
              fontFeatures: [
                FontFeature.tabularFigures(),
              ],
            ),
            controller: rsaSignatureEditingController,
            decoration: InputDecoration(
              border: OutlineInputBorder(),
              labelText: 'Serialised Signature',
            ),
          ),
          RaisedButton(
            child: Text('Sign with RSA Private Key'),
            onPressed: () {
              _reloadKeyPair();
              if (keyPair?.privateKey == null) {
                return;
              }
              if (plainTextEditingController.text.isEmpty) {
                _showDialog(
                    'Missing Data', 'Missing private key or plain text');
                return;
              }
              final dataToSign = utf8.encode(plainTextEditingController.text);
              final serializedSignature =
                  sign(privateKey: keyPair!.privateKey!, data: dataToSign);

              setState(() {
                rsaSignatureEditingController.text = serializedSignature;
              });
            },
          ),
          SizedBox(height: 5),
          Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: <Widget>[
              Flexible(
                child: RaisedButton(
                  child: Text('Verify with RSA Public Key'),
                  onPressed: () {
                    _reloadKeyPair();
                    if (keyPair?.publicKey == null) {
                      return;
                    }
                    if (rsaSignatureEditingController.text.isEmpty) {
                      _showDialog('Missing Data',
                          'Missing public key or serialised signature');
                      return;
                    }

                    try {
                      final result = verify(
                          publicKey: keyPair!.publicKey!,
                          serializedSignature:
                              rsaSignatureEditingController.text);

                      setState(() {
                        rsaVerifyEditingController.text =
                            result ? 'Success' : 'Failed';
                      });
                    } catch (e) {
                      _showDialog('Malformed Signature', '$e');
                      setState(() {
                        rsaVerifyEditingController.text = 'Failed';
                      });
                    }
                  },
                ),
              ),
              SizedBox(width: 5),
              Flexible(
                child: TextField(
                  maxLines: 1,
                  controller: rsaVerifyEditingController,
                  decoration: InputDecoration(
                    border: OutlineInputBorder(),
                    labelText: 'Verification Result',
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  void _reloadKeyPair() {
    try {
      final pair = KeyPair()
        ..loadPrivateKeyFromPKCS1PemString(privateKeyEditingController.text)
        ..loadPublicKeyFromPKCS1PemString(publicKeyEditingController.text);
      setState(() {
        keyPair = pair;
      });
    } catch (e) {
      _showDialog('Cannot parse private key/public key', 'Invalid format');
      keyPair = null;
    }
  }
}
