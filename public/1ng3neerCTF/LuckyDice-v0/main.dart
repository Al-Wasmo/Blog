import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'dart:math';


int RandomInRange(int a, int b) {
  final random = Random();
  return a + Random().nextInt(b - a + 1);
} 

void main() {
  runApp(const MyApp());
}

[...]

void roll_dice(BuildContext context, int a, int b) {
  int val = RandomInRange(a, b);
  


  if (val == 0xdeadc0de) {
    [...]
  } else {
    List<int> sequence = [];
    for (int i = 0; i < 200; i++) {
      if (i == 0) {
        sequence.add(0);
      } else if (i == 1) {
        sequence.add(1);
      } else {
        sequence.add(sequence[i - 1] + sequence[i - 2]);
      }
    }
  }
}



class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Lucky Dice',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
      ),
      home: MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {
  MyHomePage({super.key});

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int idx = 2;
  List<Image> imgs = [];
  List<String> msgs = [
    "(╬ Ò﹏Ó)",
    "(ꐦ ಠ皿ಠ )",
    "(╯°□°)╯",
    "(┛◉Д◉)┛彡┻━┻",
    "(ﾉ≧∇≦)ﾉ ﾐ ┸━┸",
    "(ﾉ｀Д´)ﾉ︵┻━┻☆",
    "(╯‵□′)╯︵┻━┻",
    "(¬_¬)",
    "(ಠ_ಠ)",
    "(︶︹︶)",
    "(；￣Д￣)ﾉｼ",
    "(ﾉ｀◎´)ﾉ ~┻━┻",
    "maYbe leSS roll_diceinG, mOrE reving ?",
  ];

  void animateDomino() async {
    for (var i = 0; i < 10; i++) {
      await Future.delayed(Duration(milliseconds: 50));
      setState(() {
        idx = RandomInRange(1, 27);
      });
    }
    ScaffoldMessenger.of(context).clearSnackBars();
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          msgs[RandomInRange(0, msgs.length - 1)],
          textAlign: TextAlign.center,
        ),
      ),
    );
  }

  [...]
 
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: GestureDetector(
        onTap: () {
          animateDomino();
          roll_dice(context, 0, 26);
        },
        child: Stack(
          children: [
            Image(
              image: AssetImage("assets/bg.jpg"),
              height: MediaQuery.of(context).size.height,
              fit: BoxFit.fill,
            ),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: [
                    Transform(
                      alignment: Alignment.center,
                      transform: Matrix4.rotationZ(3.14 / 2),
                      child: imgs[idx],
                    ),
                  ],
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
