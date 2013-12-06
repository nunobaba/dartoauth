library oauth_test;

import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:oauth/testing.dart';
import 'package:unittest/unittest.dart';


void main() {
  var mc = new MockOaClient();

  group('Leg 1', () {
    
    test('#nonce length', () {
      final Random random = new Random(new DateTime.now().millisecond);
      final SHA1 sha1 = new SHA1();
      sha1.add([random.nextInt(64)]);
      final nonce = CryptoUtils.bytesToHex(sha1.close());
      
      expect(mc.nonce.length, equals(nonce.length));
    });
    
    test('#token: signature key', () {
      var sigkey = Uri.encodeComponent(mc.consumerSecret) + '&';
      expect(mc.sigKey, equals(sigkey));
    });
    
    test('#token: signature base', () {
      // Verify the signature base starts with a POST string in uppercase. 
      final headStartPat = new RegExp(r'POST');
      expect(mc.sigBase.startsWith(headStartPat), isTrue);
    });
    
    test('#token: signature header request', () {
      // Verify the header request starts with OAuth typed as is.
      final headStartPat = new RegExp(r'OAuth');
      expect(mc.headerRequest.startsWith(headStartPat), isTrue);
    });
  });
  
  
//  group('Verifier token', () {
//  });
  
  
}



