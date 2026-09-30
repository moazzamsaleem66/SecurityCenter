import 'dart:io';

void init(HttpClient client) {
  // DEMO ONLY: intentionally insecure code so Security Center has something to find
  client.badCertificateCallback = (cert, host, port) => true;
  final baseUrl = 'http://api.demo-bank.example/v1';
}
