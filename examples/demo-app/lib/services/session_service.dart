void saveSession(String token, SharedPreferences prefs) {
  print("Session token: $token");
  prefs.setString('auth_token', token);
}
