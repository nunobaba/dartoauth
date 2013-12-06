library oauth;

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart';


/** 
 * A composable API for authenticating against OAuth and OpenId providers, 
 * typically to log into Twitter and Yahoo accounts. 
 */
abstract class OAuth {
  static const SIGMETHOD = 'HMAC-SHA1';
  static const VERSION = '1.0';
  
  Uri get requestTokenUri;
  Uri get callbackUri; 
  Uri get accessTokenUri;
  Uri get authorizeUri;
  Uri get authenticateUri;
  
  // Application key pairs.
  String consumerKey;
  String consumerSecret;
  
  // Authorization token pairs.
  String _token;
  String _tokenSecret;
  
  // Authentication token pairs.
  String oauthToken;
  String oauthTokenSecret;
  
  /// User ID and screen name are beyond the OAuth specs, subclasses
  /// will need to define them accordingly.
  String uid;
  String uname;
  
  /// Parameters map used to build to signatures.
  final Map _payload = {};

  /** 
   * Convert keys and values of a regular map into a query string. 
   * 
   * The key/value pair is jointed by [pair] string, each of them glued to 
   * the rest by [glue] with or without double quote.
   */
  String mapToString(Map map, 
                     {String pair: '=', String glue: '&', bool quote: false}) {
    final List qstring = [];
    map.forEach((k, v) => 
        qstring.add('oauth_${quote ? '$k$pair"$v"' : '$k$pair$v'}'));
    return qstring.join(glue);
  }
              
  /// Utility function as the OAuth requires plenty of parameters to be 
  /// percentage encode.
  final _encode = Uri.encodeComponent;
  
  /// Http client for requests.
  final Client _client = new Client();
  
  int _timeStamp;
  
  int createTimeStamp() => new DateTime.now().millisecondsSinceEpoch ~/ 1000;
  
  void stampTime() {
    _timeStamp = createTimeStamp();
  }
  
  /** 
   * Provide a string time stamp or create a new one.
   */
  int get timeStamp => _timeStamp == null ? 
      _timeStamp = createTimeStamp() : _timeStamp; 
  
  String _nonce;
  
  String _createNonce() {
    final Random random = new Random(new DateTime.now().millisecond);
    final SHA1 sha1 = new SHA1();
    sha1.add([random.nextInt(64)]);
    return CryptoUtils.bytesToHex(sha1.close());
  }

  /** 
   * Provide a nonce or create a new one.
   */
  String get nonce => _nonce == null ? _nonce = _createNonce() : _nonce;

  /** 
   * The signature base.
   */
  String get sigBase {
    _payload.addAll({'callback': _encode(callbackUri.toString()),
                     'consumer_key': _encode(consumerKey),
                     'nonce': _encode(nonce),
                     'signature_method': _encode(SIGMETHOD),
                     'timestamp': timeStamp.toString(),
                     'version': VERSION});
    
    return ['POST', 
            _encode((_token == null 
              ? requestTokenUri : accessTokenUri).toString()),
            _encode(mapToString(_payload))
           ].join('&');
  }

  /** 
   * Signature key.
   */
  String get sigKey { 
    var k = _encode(consumerSecret) + '&';
    if (_tokenSecret != null) k += tokenRequest;
    return k;
  }
  
  /** 
   * The OAuth signature.
   */
  String get oauthSig {
    final HMAC hmac = new HMAC(new SHA1(), sigKey.codeUnits);
    hmac.add(sigBase.codeUnits);
    return CryptoUtils.bytesToBase64(hmac.digest);
  }
  
  String get headerRequest => 
      'OAuth ${mapToString(_payload, glue: ',', quote: true)}';
  
  /** 
   * The authorization request.
   */
  String get tokenRequest {
    if (!_payload.containsKey('signature')) 
      _payload.addAll({'signature': _encode(oauthSig)});
    
    return headerRequest;
  }
  
  /**
   * This takes the same payload than for step 1, except the nonce and 
   * signature which need to be renewed.
   */
  String get accessTokenRequest {
    if (!_payload.containsKey('token')) 
      _payload.addAll({'token': _encode(_token)});
    _payload['signature'] = _encode(oauthSig);
    
    return headerRequest;
  }
  
  /**
   * Handle the request of a new token.
   */
  void handleTokenRequest(HttpRequest req) {
    _client.post(requestTokenUri, headers: {'authorization': tokenRequest})
      .then((resp) {
        var data = Uri.splitQueryString(resp.body);
        _token = data['oauth_token'];
        _tokenSecret = data['oauth_token_secret'];
      })
      .then((_) =>
        req.response.redirect(Uri.parse(
            authenticateUri.toString() + '?oauth_token=$_token'))
      );
  }

  /**
   * Handle the validation of the OAuth authentication token. 
   */
  void handleValidToken(HttpRequest req) {
    // Tokens given in step 1 and returned by the provider have to match. 
    if (req.uri.queryParameters['oauth_token'] == _token) {
      
      _client.post(accessTokenUri, 
          headers: {'authorization': accessTokenRequest}, 
          fields: {'oauth_verifier': req.uri.queryParameters['oauth_verifier']})
        .then(handleOauthToken)
        .then((it) => handleFinale(it, req))
        .catchError((msg) => print(msg));
    } else
      throw new Exception('Request Token and verifier do NOT match.');
  }
  
  /// Handle the response from provider, what to do with access token, 
  /// access token secret and out of scope fields like user ID or screen name.
  Future handleOauthToken(Response resp);
  
  /// Handle how the OAuth process ends, e.g. with a redirection to a
  /// specific page or close the original request. 
  Future handleFinale(data, HttpRequest request);
}
