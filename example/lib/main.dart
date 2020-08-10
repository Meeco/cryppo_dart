import 'package:demo/gcm_page.dart';
import 'package:demo/rsa_page.dart';
import 'package:flutter/material.dart';

void main() async {
  runApp(CryppoDemoApp());
}

class CryppoDemoApp extends StatefulWidget {
  @override
  _CryppoDemoAppState createState() => _CryppoDemoAppState();
}

class _CryppoDemoAppState extends State<CryppoDemoApp> {
  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () {
        FocusScope.of(context).requestFocus(new FocusNode());
      },
      child: MaterialApp(
        title: 'Cryppo Demo',
        home: BottomTabBar(),
      ),
    );
  }
}

class BottomTabBar extends StatefulWidget {
  BottomTabBar({Key key}) : super(key: key);

  @override
  _BottomTabBarState createState() => _BottomTabBarState();
}

class _BottomTabBarState extends State<BottomTabBar> {
  int _selectedIndex = 0;
  static const pageTitles = ['RSA', 'AES', 'File'];
  static List<Widget> _widgetOptions = <Widget>[
    RsaPage(),
    GcmPage(),
  ];

  void _onItemTapped(int index) {
    setState(() {
      _selectedIndex = index;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(pageTitles[_selectedIndex]),
      ),
      body: Center(
        child: _widgetOptions.elementAt(_selectedIndex),
      ),
      bottomNavigationBar: BottomNavigationBar(
        items: const <BottomNavigationBarItem>[
          BottomNavigationBarItem(
            icon: Icon(Icons.enhanced_encryption),
            title: Text('RSA'),
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.lock),
            title: Text('AES'),
          ),
        ],
        currentIndex: _selectedIndex,
        selectedItemColor: Colors.amber[800],
        onTap: _onItemTapped,
      ),
    );
  }
}
