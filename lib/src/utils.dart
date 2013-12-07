library utils;

/** 
 * Join keys and values of a regular map into a query string. 
 * 
 * The key/value pair is jointed by [pair] string, each of them glued to 
 * the rest by [glue] with or without double quote.
 */
String joinMap(Map map,
               {String pair: '=', String glue: '&', bool quote: false}) {
  
  final List qstring = [];
  map.forEach((k, v) => qstring.add(
      'oauth_${quote ? '$k$pair"$v"' : '$k$pair$v'}'));
  
  return qstring.join(glue);
}