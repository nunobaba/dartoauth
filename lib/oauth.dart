library oauth;

import 'dart:async';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

/**
 * A general consumer client for OAuth 1.0a. 
 * 
 * It can whether be used right out of the box to connect to Twitter, 
 * or customized for other providers by overriding the pair of methods:
 * the [_headAccessRequest] method to cook parameters for the access 
 * token and the [_processOauthToken] method to process received user key
 * and secret. 
 * 
 * The first OAuth step, i.e. the request token step, is assumed to be 
 * the same all the time.    
 */
class OAuth {
  static const SIGNATURE_METHOD = 'HMAC-SHA1';
  static const VERSION = '1.0';
  
  String consumerKey, consumerSecret,
         token, tokenSecret, 
         userKey, userSecret,
         requestTokenUrl, authorizeUrl, accessTokenUrl,
         callbackUrl;
  
  /// Parameters for signature base.
  Map<String, String> buffer;
  /// Extra request headers, as providers add their specifics.
  Map<String, String> xheaders;
  
  http.Client client;
  
  OAuth(this.consumerKey, this.consumerSecret, 
        this.requestTokenUrl, this.authorizeUrl, this.accessTokenUrl,
        this.callbackUrl) {
    
    client = new http.Client();
    // Buffer is filled with persistent request parameters.  
    buffer = {'version': VERSION,
              'signature_method': SIGNATURE_METHOD,
              'consumer_key': Uri.encodeComponent(consumerKey),
              'callback': Uri.encodeComponent(callbackUrl)}; 
  }
  
  void handleAuthorization(HttpRequest req) {
    signBuffer(requestTokenUrl);

    client.post(requestTokenUrl, 
        headers: {
          'Accept': '*/*',
          'User-Agent': 'Dart authentication',
          'Authorization': headRequest()})
      .then((resp) {
        final data = Uri.splitQueryString(resp.body);
        if (data['oauth_callback_confirmed'] == 'true') {
          token = data['oauth_token'];
          tokenSecret = data['oauth_token_secret'];
          req.response.redirect(Uri.parse('$authorizeUrl?oauth_token=$token'));
        } else {
          print('Error: ${resp.body}');
          return new Future.error('NO request token.');
        }
      })
      .catchError((msg) => print(msg));
  }
  
  void handleAccess(HttpRequest req) {
    final data = req.uri.queryParameters;
    if (data['oauth_token'] == token) {
      // The authorization token always get enclosed.
      buffer['token'] = Uri.encodeComponent(token);
      
      client.post(accessTokenUrl, 
          headers: headAccessRequest(data))
        .then((resp) {
          final data = Uri.splitQueryString(resp.body);
          if (data.containsKey('oauth_token')) {
            processOauthToken(data, req);
          } else { 
            return new Future.error('NO access token');
          }
        })
        .catchError((msg) {
          print(msg);
          req.response.close();
        });
      
    } else req.response.close();
  }

  /// Arrange buffer parameters to exchange the authorization token for
  /// the access token. Keep in mind this method is set for Twitter.
  Map<String, String> headAccessRequest(Map data) {
    // Renew the signature after adding token as the new parameter.
    signBuffer(accessTokenUrl);

    // Add the verifier in the header and the request body.
    buffer['verifier'] = data['oauth_verifier'];
    
    return {'authorization': headRequest()};
  }

  /// Handle the process of oauth token. 
  /// Override this for specific needs or providers. 
  Future processOauthToken(Map data, HttpRequest req) {
    userKey = data['oauth_token'];
    userSecret = data['oauth_token_secret'];
  }
  
  String headRequest() => 
      'OAuth ${joinedBuffer(glue: ',', quote: true)}';
  
  void signBuffer(url, [String method = 'post']) {
    // Renew timestamp and nonce.
    _addNonceAndTimestamp();
    // Clean buffer from any previous signature.
    if (buffer.containsKey('signature')) 
      buffer.remove('signature');
    
    // .. Build signature base.
    final base = [method.toUpperCase(), 
                  Uri.encodeComponent(url),
                  Uri.encodeComponent(joinedBuffer())
                 ].join('&');
    
    // .. Get signature key.
    final cipher = 
        '${Uri.encodeComponent(consumerSecret)}&'
        '${userSecret != null ? Uri.encodeComponent(userSecret) : 
           tokenSecret != null ? Uri.encodeComponent(tokenSecret) : ''}';
    
    // .. Sign base.
    final hmac = new HMAC(new SHA1(), cipher.codeUnits);
    hmac.add(base.codeUnits);
    
    final signature = CryptoUtils.bytesToBase64(hmac.close());
    buffer['signature'] = Uri.encodeComponent(signature);
  }

  /// Provide a nonce and timestamp to the buffer. 
  void _addNonceAndTimestamp() {
    buffer['nonce'] = _nonce();
    buffer['timestamp'] = _timestamp();
  }
  
  int _nounceIncrement = 0;
  final _shaFoundry = new SHA1();
  
  String _nonce() {
    final sha = _shaFoundry.newInstance();
    sha.add([++_nounceIncrement, new DateTime.now().millisecond]);
    return CryptoUtils.bytesToHex(sha.close());
  }
  
  String _timestamp() =>
      (new DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
  
  /** 
   * Alphabetically join keys and values of a regular map into a query string. 
   * 
   * The key/value pair is jointed by [pair] string, each of them glued to 
   * the rest by [glue] with or without double quote.
   */
  String joinedBuffer({String eq: '=', String glue: '&', bool quote: false}) {
    final List buf = [];
    final q = quote ? '"' : '';
    
    // Keys in [parameters] need to be sorted alphabetically.  
    buffer.keys.toList()
      ..sort()
      ..forEach((p) => buf.add('oauth_$p$eq$q${buffer[p]}$q'));
    
    return buf.join(glue);
  }

  
}



