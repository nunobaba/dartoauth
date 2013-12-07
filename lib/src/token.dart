library token;

import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:quiver/strings.dart' show isBlank;
import 'utils.dart';


class Token {
  static const SIGNATURE_METHOD = 'HMAC-SHA1';
  static const VERSION = '1.0';
  
  String callbackUrl;
  
  String consumerKey;
  String consumerSecret;
  
  String token;
  String tokenSecret;
  
  String verifier;
  
  String accessToken;
  String accessSecret;
  
  Token();
  
  /// Utility function as the OAuth requires plenty of parameters to be 
  /// percentage encode.
  final _enc = Uri.encodeComponent;
  
  int _timeStamp;

  String _nonce;
  
  /// Create a time stamp and a nonce.
  void createTimeAndNonce() {
    final now = new DateTime.now(); 
    final Random random = new Random(now.millisecond);
    final SHA1 sha1 = new SHA1();
    sha1.add([random.nextInt(8), random.nextInt(8)]);
    _nonce = CryptoUtils.bytesToHex(sha1.close());
    _timeStamp = now.millisecondsSinceEpoch ~/ 1000;
  }
  
  /// The run stage of the OAuth 3-leg dance:
  /// - 1 : Authorization token simply requested.
  /// - 2 : Authorization token validated.
  /// - 3 : Access token received.
  int get runStage => 
      isBlank(token) ? 1 : (isBlank(accessToken) ? 2 : 3);
  
  Map<String, String> get _params { 
    final prms = {'callback': _enc(callbackUrl),
                  'consumer_key': _enc(consumerKey),
                  'nonce': _enc(_nonce),
                  'signature_method': SIGNATURE_METHOD,
                  'timestamp': _timeStamp.toString(),
                  'version': VERSION};
    
    if (token != null) prms['token'] = _enc(token);
    return prms;
  }
    
  /// The signature key.
  String get signKey =>
      '${_enc(consumerSecret)}&'
      '${tokenSecret != null ? _enc(tokenSecret) : ''}';
    
  /// Provide a signature base for the [uri] which could be a [Uri] object
  /// or a [String]. Requests are arbitrary only with 'POST' method.
  String signBase(uri) {
    final url = uri is String ? uri : uri.toString();
    return ['POST', _enc(url), _enc(joinMap(_params))].join('&');
  }
  
  String sign(uri) {
    final HMAC hmac = new HMAC(new SHA1(), signKey.codeUnits);
    hmac.add(signBase(uri).codeUnits);
    return CryptoUtils.bytesToBase64(hmac.digest);
  }
  
  String getAuthHeader(uri) {
    // Always renew time stamp and nonce.
    createTimeAndNonce();

    final params = _params;
    params['signature'] = _enc(sign(uri));
    
    // Additional fields are required in stage 2 and 3.
    if (verifier != null) params['verifier'] = verifier;
    if (token != null) params['token'] = token;
    
    final query = 'OAuth ${joinMap(params, glue: ',', quote: true)}';
    return query;
  }
  
}



