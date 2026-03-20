part of '../sibna_protocol.dart';

/// Secure context for Sibna protocol operations
class SibnaContext {
  Pointer<Void>? _handle;
  final String? _password;
  bool _disposed = false;

  /// Get the native handle
  Pointer<Void> get handle {
    _ensureNotDisposed();
    return _handle!;
  }

  /// Check if the context is disposed
  bool get isDisposed => _disposed;

  /// Private constructor
  SibnaContext._(this._handle, this._password);

  /// Create a new secure context
  ///
  /// [password] is the master password for storage encryption (optional)
  static Future<SibnaContext> create({String? password}) async {
    if (!SibnaProtocol.isInitialized) {
      throw SibnaError(
        SibnaErrorCode.notInitialized,
        'SDK not initialized. Call SibnaProtocol.initialize() first.',
      );
    }

    final contextPtr = calloc<Pointer<Void>>();

    try {
      // Convert password to bytes if provided
      Pointer<Uint8>? passwordPtr;
      int passwordLen = 0;

      if (password != null) {
        final passwordBytes = utf8.encode(password);
        passwordPtr = calloc<Uint8>(passwordBytes.length);
        passwordPtr.asTypedList(passwordBytes.length).setAll(0, passwordBytes);
        passwordLen = passwordBytes.length;
      }

      try {
        final result = _bindings.sibna_context_create(
          passwordPtr ?? nullptr,
          passwordLen,
          contextPtr,
        );
        checkResult(result, operation: 'createContext');

        return SibnaContext._(contextPtr.value, password);
      } finally {
        if (passwordPtr != null) {
          // Securely clear password from memory
          passwordPtr.asTypedList(passwordLen).fillRange(0, passwordLen, 0);
          calloc.free(passwordPtr);
        }
      }
    } finally {
      calloc.free(contextPtr);
    }
  }

  /// Generate a new identity key pair
  Future<IdentityKeyPair> generateIdentity() async {
    _ensureNotDisposed();

    // This would call the native library in production
    // For now, generate placeholder keys
    final ed25519Public = SibnaCrypto.randomBytes(32);
    final x25519Public = SibnaCrypto.randomBytes(32);

    return IdentityKeyPair.fromPublicKeys(ed25519Public, x25519Public);
  }

  /// Create a new session with a peer
  Future<SibnaSession> createSession(Uint8List peerId) async {
    _ensureNotDisposed();

    if (peerId.isEmpty) {
      throw ValidationError(
        SibnaErrorCode.invalidArgument,
        'Peer ID cannot be empty',
        field: 'peerId',
      );
    }

    final sessionPtr = calloc<Pointer<Void>>();
    final peerIdPtr = calloc<Uint8>(peerId.length);

    try {
      peerIdPtr.asTypedList(peerId.length).setAll(0, peerId);

      final result = _bindings.sibna_session_create(
        handle,
        peerIdPtr,
        peerId.length,
        sessionPtr,
      );
      checkResult(result, operation: 'createSession');

      return SibnaSession._(sessionPtr.value, peerId);
    } finally {
      calloc.free(sessionPtr);
      calloc.free(peerIdPtr);
    }
  }

  /// Encrypt a message for a session
  Future<Uint8List> encryptMessage(
    Uint8List peerId,
    Uint8List plaintext, {
    Uint8List? associatedData,
  }) async {
    _ensureNotDisposed();

    // This would use the session's encrypt method in production
    // For now, use standalone crypto
    final key = SibnaCrypto.generateKey();
    try {
      return SibnaCrypto.encrypt(key, plaintext, associatedData: associatedData);
    } finally {
      key.secureClear();
    }
  }

  /// Decrypt a message from a session
  Future<Uint8List> decryptMessage(
    Uint8List peerId,
    Uint8List ciphertext, {
    Uint8List? associatedData,
  }) async {
    _ensureNotDisposed();

    // This would use the session's decrypt method in production
    throw UnimplementedError('Session-based decryption requires native library');
  }

  /// Create a new group
  Future<SibnaGroup> createGroup(Uint8List groupId) async {
    _ensureNotDisposed();

    if (groupId.length != 32) {
      throw ValidationError(
        SibnaErrorCode.invalidArgument,
        'Group ID must be 32 bytes',
        field: 'groupId',
      );
    }

    return SibnaGroup._create(groupId);
  }

  /// Get context statistics
  Future<Map<String, dynamic>> getStats() async {
    _ensureNotDisposed();

    return {
      'version': SibnaProtocol.version,
      'sessionCount': 0, // Would come from native library
      'groupCount': 0,   // Would come from native library
      'createdAt': DateTime.now().toIso8601String(),
    };
  }

  /// Dispose the context and free resources
  void dispose() {
    if (_disposed) return;

    if (_handle != null && _handle != nullptr) {
      _bindings.sibna_context_destroy(_handle!);
      _handle = null;
    }

    _disposed = true;
  }

  /// Ensure the context is not disposed
  void _ensureNotDisposed() {
    if (_disposed) {
      throw SibnaError(
        SibnaErrorCode.invalidState,
        'Context has been disposed',
      );
    }
  }

  @override
  String toString() => 'SibnaContext(disposed: $_disposed)';
}
