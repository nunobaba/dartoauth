library oauth;

import 'dart:async';
import 'dart:io';
import 'package:http/http.dart';
import 'src/token.dart';


/** 
 * A composable API for authenticating against OAuth and OpenId providers, 
 * typically to log into Twitter and Yahoo accounts. 
 */
abstract class OAuth {
  Uri get requestTokenUri;
  Uri get callbackUri; 
  Uri get authenticateUri;
  Uri get accessTokenUri;
  Uri get authorizeUri;
  
  // Application key pairs.
  String get consumerKey;
  String get consumerSecret;
  
  Token _token = new Token();
  
  Token get token => _token;
  
  /// Http client for requests.
  final Client _client = new Client();

  Map<String, String> get xheaders;
  
  /// Handle the request of a signin using OAuth, starting at 
  /// stage 1, acquiring a new authentication token.
  void handleTokenRequest(HttpRequest req) {
    _token..callbackUrl = callbackUri.toString()
          ..consumerKey = consumerKey
          ..consumerSecret = consumerSecret;
    
    _client.post(requestTokenUri, 
        headers: {'authorization': _token.getAuthHeader(requestTokenUri)})
      .then((resp) {
        var data = Uri.splitQueryString(resp.body);
        _token.token = data['oauth_token'];
        _token.tokenSecret = data['oauth_token_secret'];
      
        print('#token body: ${Uri.decodeComponent(resp.body)}');

        // Stage 2! redirect request to url where user acknowledges the demand. 
        req.response.redirect(Uri.parse(
            '${authenticateUri}?oauth_token=${_token.token}'));
      });
  }

  /// Handle the validation of the OAuth authentication token.
  /// This is stage 3, acquiring the authorization token to be exchanged
  /// for the access token.
  void handleValidToken(HttpRequest req) {
    // The token given in stage 1 and this one returned by the provider 
    // have to match. 
    if (req.uri.queryParameters['oauth_token'] == _token.token) {
      _token.verifier = req.uri.queryParameters['oauth_verifier'];
      
      // Some providers require specific parameters to be added.
      final headers = {'authorization': _token.getAuthHeader(accessTokenUri)};
      headers.addAll(xheaders);
      
      print('#Validation headers: ${headers}');
      
      _client.post(accessTokenUri, headers: headers,
          fields: {'oauth_verifier': _token.verifier})
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
