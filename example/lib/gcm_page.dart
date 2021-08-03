import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:cryppo/cryppo.dart';
import 'package:flutter/material.dart';

class GcmPage extends StatefulWidget {
  @override
  _GcmPageState createState() => _GcmPageState();
}

class _GcmPageState extends State<GcmPage> {
  final passphraseEditingController = TextEditingController();
  final serialisedDerivationArtefactsEditingController =
      TextEditingController();
  final derivedKeyEditingController = TextEditingController();
  final serialisedEncryptedDataEditingController = TextEditingController();
  final plainTextEditingController = TextEditingController();

  void _showDialog(String title, String content) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (_) => AlertDialog(
        title: Text(title),
        content: Text(content),
        actions: <Widget>[
          TextButton(
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
    return ListView(
      children: <Widget>[
        Container(
          margin: EdgeInsets.symmetric(vertical: 4, horizontal: 8),
          padding: EdgeInsets.all(8),
          decoration: BoxDecoration(
            border: Border.all(color: Colors.blueAccent),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Center(child: Text('Derive a key')),
              TextField(
                controller: passphraseEditingController,
                decoration: InputDecoration(labelText: 'Passphrase'),
              ),
              TextField(
                controller: serialisedDerivationArtefactsEditingController,
                decoration: InputDecoration(
                    labelText: 'Serialised Derivation Artefacts'),
              ),
              ElevatedButton(
                child: Text('Generate Random Artifacts'),
                onPressed: () async {
                  try {
                    final artefacts = DerivationArtefacts.generate();
                    setState(() {
                      serialisedDerivationArtefactsEditingController.text =
                          artefacts.serialize();
                    });
                  } catch (e) {
                    _showDialog('Error', e.toString());
                  }
                },
              ),
              ElevatedButton(
                child: Text('Derive key'),
                onPressed: () async {
                  if (passphraseEditingController.text == '' ||
                      serialisedDerivationArtefactsEditingController.text ==
                          '') {
                    return;
                  }
                  try {
                    final derivedKey = await deriveKeyWithSerializedOptions(
                        passphraseEditingController.text,
                        serialisedDerivationArtefactsEditingController.text);
                    setState(() {
                      derivedKeyEditingController.text =
                          hex.encode(derivedKey.key.bytes);
                    });
                  } catch (e) {
                    _showDialog('Error', e.toString());
                  }
                },
              ),
              TextField(
                controller: derivedKeyEditingController,
                decoration: InputDecoration(
                  labelText: 'Derived Key (hex)',
                ),
              ),
            ],
          ),
        ),
        Container(
          margin: EdgeInsets.symmetric(vertical: 4, horizontal: 8),
          padding: EdgeInsets.all(8),
          decoration: BoxDecoration(
            border: Border.all(color: Colors.blueAccent),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Center(child: Text('Encrypt')),
              TextField(
                controller: passphraseEditingController,
                decoration: InputDecoration(labelText: 'Passphrase'),
              ),
              TextField(
                controller: serialisedDerivationArtefactsEditingController,
                decoration: InputDecoration(
                    labelText: 'Serialised Derivation Artefacts'),
              ),
              TextField(
                controller: plainTextEditingController,
                decoration: InputDecoration(labelText: 'Plain Text'),
              ),
              ElevatedButton(
                child: Text('Encrypt'),
                onPressed: () async {
                  try {
                    final derivedKey = await deriveKeyWithSerializedOptions(
                        passphraseEditingController.text,
                        serialisedDerivationArtefactsEditingController.text);

                    final plainText = plainTextEditingController.text;

                    final encrypted = await encryptWithKey(
                        data: utf8.encode(plainText),
                        encryptionStrategy: EncryptionStrategy.aes256Gcm,
                        key: derivedKey.key);
                    setState(() {
                      serialisedEncryptedDataEditingController.text =
                          encrypted.serialize();
                    });
                  } catch (e) {
                    _showDialog('Error', e.toString());
                  }
                },
              ),
              TextField(
                controller: serialisedEncryptedDataEditingController,
                decoration:
                    InputDecoration(labelText: 'Serialised Encrypted Text'),
              ),
            ],
          ),
        ),
        Container(
          margin: EdgeInsets.symmetric(vertical: 4, horizontal: 8),
          padding: EdgeInsets.all(8),
          decoration: BoxDecoration(
            border: Border.all(color: Colors.blueAccent),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Center(child: Text('Decrypt')),
              TextField(
                controller: passphraseEditingController,
                decoration: InputDecoration(labelText: 'Passphrase'),
              ),
              TextField(
                controller: serialisedDerivationArtefactsEditingController,
                decoration: InputDecoration(
                    labelText: 'Serialised Derivation Artefacts'),
              ),
              TextField(
                controller: serialisedEncryptedDataEditingController,
                decoration:
                    InputDecoration(labelText: 'Serialised Encryption Data'),
              ),
              ElevatedButton(
                child: Text('Decrypt'),
                onPressed: () async {
                  try {
                    final derivedKey = await deriveKeyWithSerializedOptions(
                        passphraseEditingController.text,
                        serialisedDerivationArtefactsEditingController.text);
                    final decrypted = await decryptWithKey(
                      key: derivedKey.key,
                      encrypted: serialisedEncryptedDataEditingController.text,
                    );
                    setState(() {
                      plainTextEditingController.text = utf8.decode(decrypted);
                    });
                  } catch (e) {
                    _showDialog('Error', e.toString());
                  }
                },
              ),
              TextField(
                controller: plainTextEditingController,
                decoration: InputDecoration(
                  labelText: 'Decrypted Text',
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}
