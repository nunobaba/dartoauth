/**
 * This library contains testing classes for the OAuth library.
 * 
 * The [MockOaClient] class is a drop-in oauth client that is set with generic
 * consumer key and secret, to fake a a client that generates its own 
 * signature base and keys.
 */
library oauth.testing;

import 'dart:async';
import 'dart:io';
import 'oauth.dart';
import 'package:http/http.dart';
import 'package:quiver/strings.dart' show isBlank;


/// Simple subclass of OAuth implementing all abstract getters and methods.
class MockOaClient extends OAuth {
  Uri get requestTokenUri => 
      Uri.parse('https://api.twitter.com/oauth/request_token');
  Uri get callbackUri =>
      Uri.parse('http://127.0.0.1:3000/tw/token');
  Uri get authorizeUri =>
      Uri.parse('https://api.twitter.com/oauth/authorize');
  Uri get accessTokenUri =>
      Uri.parse('https://api.twitter.com/oauth/access_token');
  Uri get authenticateUri => 
      Uri.parse('https://api.twitter.com/oauth/authenticate');
  
  String get consumerKey => 'nHBYgYRllYSQeEhEpXzmg';
  String get consumerSecret => 'cr5F8Y2xic3qvg1jmSV7UqtLb7bRW2UBXcEjkEnk';
  Map get xheaders => {};
  
  Future handleOauthToken(Response resp) {
    final creds = Uri.splitQueryString(resp.body);
    oauthToken = creds['oauth_token'];
    oauthTokenSecret = creds['oauth_token_secret'];
    uid = creds['user_id'];
    uname = creds['screen_name'];
    return new Future.value(uname);
  }
  
  Future handleFinale(uname, HttpRequest req) {
    if (!isBlank(uname)) {
      req.response.redirect(Uri.parse(r'/'));
    } else {
      // Not authenticated, go back to main.
      req.response.redirect(Uri.parse(r'/'));
    }
  }
}


