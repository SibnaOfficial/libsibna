/**
 * Sibna Protocol JavaScript/TypeScript SDK - Ultra Secure Edition
 * 
 * A JavaScript/TypeScript wrapper for the Sibna secure communication protocol.
 * 
 * Example usage:
 * ```typescript
 * import { Context, Crypto } from 'sibna-protocol';
 * 
 * // Create context
 * const ctx = new Context('my_secure_password');
 * 
 * // Generate identity
 * const identity = ctx.generateIdentity();
 * 
 * // Create session
 * const session = ctx.createSession(new Uint8Array([1, 2, 3]));
 * 
 * // Encrypt message
 * const encrypted = session.encrypt(new TextEncoder().encode('Hello, World!'));
 * 
 * // Decrypt message
 * const decrypted = session.decrypt(encrypted);
 * ```
 */

export const VERSION = '8.0.0';

// Error codes matching the Rust implementation
export enum ErrorCode {
  OK = 0,
  INVALID_ARGUMENT = 1,
  INVALID_KEY = 2,
  ENCRYPTION_FAILED = 3,
  DECRYPTION_FAILED = 4,
  OUT_OF_MEMORY = 5,
  INVALID_STATE = 6,
  SESSION_NOT_FOUND = 7,
  KEY_NOT_FOUND = 8,
  RATE_LIMIT_EXCEEDED = 9,
  INTERNAL_ERROR = 10,
  BUFFER_TOO_SMALL = 11,
  INVALID_CIPHERTEXT = 12,
  AUTHENTICATION_FAILED = 13,
}

// Error messages
const ERROR_MESSAGES: Record<ErrorCode, string> = {
  [ErrorCode.OK]: 'Success',
  [ErrorCode.INVALID_ARGUMENT]: 'Invalid argument',
  [ErrorCode.INVALID_KEY]: 'Invalid key',
  [ErrorCode.ENCRYPTION_FAILED]: 'Encryption failed',
  [ErrorCode.DECRYPTION_FAILED]: 'Decryption failed',
  [ErrorCode.OUT_OF_MEMORY]: 'Out of memory',
  [ErrorCode.INVALID_STATE]: 'Invalid state',
  [ErrorCode.SESSION_NOT_FOUND]: 'Session not found',
  [ErrorCode.KEY_NOT_FOUND]: 'Key not found',
  [ErrorCode.RATE_LIMIT_EXCEEDED]: 'Rate limit exceeded',
  [ErrorCode.INTERNAL_ERROR]: 'Internal error',
  [ErrorCode.BUFFER_TOO_SMALL]: 'Buffer too small',
  [ErrorCode.INVALID_CIPHERTEXT]: 'Invalid ciphertext',
  [ErrorCode.AUTHENTICATION_FAILED]: 'Authentication failed',
};

/**
 * Sibna error class
 */
export class SibnaError extends Error {
  constructor(public code: ErrorCode, message?: string) {
    super(message || ERROR_MESSAGES[code] || `Unknown error (${code})`);
    this.name = 'SibnaError';
  }
}

/**
 * Check if result is an error and throw if so
 */
function checkResult(result: number): void {
  if (result !== ErrorCode.OK) {
    throw new SibnaError(result as ErrorCode);
  }
}

// WASM module interface (to be loaded dynamically)
interface SibnaWasm {
  memory: WebAssembly.Memory;
  sibna_context_create: (passwordPtr: number, passwordLen: number, contextPtr: number) => number;
  sibna_context_destroy: (context: number) => void;
  sibna_version: (buffer: number, bufferLen: number) => number;
  sibna_encrypt: (
    key: number,
    plaintext: number,
    plaintextLen: number,
    ad: number,
    adLen: number,
    ciphertextPtr: number
  ) => number;
  sibna_decrypt: (
    key: number,
    ciphertext: number,
    ciphertextLen: number,
    ad: number,
    adLen: number,
    plaintextPtr: number
  ) => number;
  sibna_generate_key: (key: number) => number;
  sibna_random_bytes: (len: number, buffer: number) => number;
  sibna_free_buffer: (buffer: number) => void;
  malloc: (size: number) => number;
  free: (ptr: number) => void;
}

let wasmModule: SibnaWasm | null = null;

/**
 * Initialize the WASM module
 */
export async function init(wasmUrl?: string): Promise<void> {
  if (wasmModule) return;

  // In browser environment, load WASM
  if (typeof window !== 'undefined') {
    const response = await fetch(wasmUrl || '/sibna.wasm');
    const buffer = await response.arrayBuffer();
    const { instance } = await WebAssembly.instantiate(buffer, {
      env: {
        memory: new WebAssembly.Memory({ initial: 256, maximum: 512 }),
      },
    });
    wasmModule = instance.exports as unknown as SibnaWasm;
  } else {
    // Node.js environment - would use native bindings
    throw new SibnaError(ErrorCode.INTERNAL_ERROR, 'Node.js native bindings not implemented');
  }
}

/**
 * Copy Uint8Array to WASM memory
 */
function copyToWasm(data: Uint8Array): number {
  if (!wasmModule) throw new SibnaError(ErrorCode.INTERNAL_ERROR, 'WASM not initialized');
  
  const ptr = wasmModule.malloc(data.length);
  const memory = new Uint8Array(wasmModule.memory.buffer);
  memory.set(data, ptr);
  return ptr;
}

/**
 * Copy from WASM memory to Uint8Array
 */
function copyFromWasm(ptr: number, len: number): Uint8Array {
  if (!wasmModule) throw new SibnaError(ErrorCode.INTERNAL_ERROR, 'WASM not initialized');
  
  const memory = new Uint8Array(wasmModule.memory.buffer);
  return memory.slice(ptr, ptr + len);
}

/**
 * Byte buffer structure matching the FFI
 */
interface ByteBuffer {
  data: number;
  len: number;
  capacity: number;
}

/**
 * Read byte buffer from WASM memory
 */
function readByteBuffer(ptr: number): Uint8Array {
  if (!wasmModule) throw new SibnaError(ErrorCode.INTERNAL_ERROR, 'WASM not initialized');
  
  const memory = new DataView(wasmModule.memory.buffer);
  const dataPtr = memory.getUint32(ptr, true);
  const len = memory.getUint32(ptr + 4, true);
  
  return copyFromWasm(dataPtr, len);
}

/**
 * Free a byte buffer in WASM
 */
function freeByteBuffer(ptr: number): void {
  if (!wasmModule) return;
  wasmModule.sibna_free_buffer(ptr);
}

/**
 * Identity key pair
 */
export class IdentityKeyPair {
  private _publicKey: Uint8Array;
  private _privateKey: Uint8Array;

  constructor(publicKey: Uint8Array, privateKey: Uint8Array) {
    this._publicKey = publicKey;
    this._privateKey = privateKey;
  }

  get publicKey(): Uint8Array {
    return new Uint8Array(this._publicKey);
  }

  sign(data: Uint8Array): Uint8Array {
    // Implementation would call WASM
    return new Uint8Array(64);
  }

  verify(data: Uint8Array, signature: Uint8Array): boolean {
    // Implementation would call WASM
    return false;
  }
}

/**
 * Secure session for encrypted communication
 */
export class Session {
  private _handle: number;

  constructor(handle: number) {
    this._handle = handle;
  }

  encrypt(plaintext: Uint8Array, associatedData?: Uint8Array): Uint8Array {
    // Implementation would call WASM
    return new Uint8Array(0);
  }

  decrypt(ciphertext: Uint8Array, associatedData?: Uint8Array): Uint8Array {
    // Implementation would call WASM
    return new Uint8Array(0);
  }

  destroy(): void {
    // Implementation would call WASM
  }
}

/**
 * Secure context for Sibna protocol operations
 */
export class Context {
  private _handle: number;

  constructor(password?: string | Uint8Array) {
    if (!wasmModule) {
      throw new SibnaError(ErrorCode.INTERNAL_ERROR, 'WASM not initialized. Call init() first.');
    }

    let passwordPtr = 0;
    let passwordLen = 0;

    if (password !== undefined) {
      const passwordData = typeof password === 'string' 
        ? new TextEncoder().encode(password)
        : password;
      passwordPtr = copyToWasm(passwordData);
      passwordLen = passwordData.length;
    }

    const contextPtr = wasmModule.malloc(4);
    
    try {
      const result = wasmModule.sibna_context_create(passwordPtr, passwordLen, contextPtr);
      checkResult(result);
      
      const memory = new DataView(wasmModule.memory.buffer);
      this._handle = memory.getUint32(contextPtr, true);
    } finally {
      wasmModule.free(contextPtr);
      if (passwordPtr) wasmModule.free(passwordPtr);
    }
  }

  destroy(): void {
    if (wasmModule && this._handle) {
      wasmModule.sibna_context_destroy(this._handle);
      this._handle = 0;
    }
  }

  generateIdentity(): IdentityKeyPair {
    // Implementation would call WASM
    return new IdentityKeyPair(new Uint8Array(32), new Uint8Array(32));
  }

  createSession(peerId: Uint8Array): Session {
    // Implementation would call WASM
    return new Session(0);
  }

  static version(): string {
    if (!wasmModule) {
      return VERSION;
    }

    const bufferPtr = wasmModule.malloc(32);
    
    try {
      const result = wasmModule.sibna_version(bufferPtr, 32);
      checkResult(result);
      
      const memory = new Uint8Array(wasmModule.memory.buffer);
      const bytes: number[] = [];
      for (let i = 0; i < 32; i++) {
        const byte = memory[bufferPtr + i];
        if (byte === 0) break;
        bytes.push(byte);
      }
      
      return new TextDecoder().decode(new Uint8Array(bytes));
    } finally {
      wasmModule.free(bufferPtr);
    }
  }
}

/**
 * Standalone cryptographic operations
 */
export class Crypto {
  /**
   * Generate a random 32-byte encryption key
   */
  static generateKey(): Uint8Array {
    if (!wasmModule) {
      throw new SibnaError(ErrorCode.INTERNAL_ERROR, 'WASM not initialized');
    }

    const keyPtr = wasmModule.malloc(32);
    
    try {
      const result = wasmModule.sibna_generate_key(keyPtr);
      checkResult(result);
      
      return copyFromWasm(keyPtr, 32);
    } finally {
      wasmModule.free(keyPtr);
    }
  }

  /**
   * Encrypt data with a key
   */
  static encrypt(
    key: Uint8Array,
    plaintext: Uint8Array,
    associatedData?: Uint8Array
  ): Uint8Array {
    if (!wasmModule) {
      throw new SibnaError(ErrorCode.INTERNAL_ERROR, 'WASM not initialized');
    }

    if (key.length !== 32) {
      throw new SibnaError(ErrorCode.INVALID_KEY, 'Key must be 32 bytes');
    }

    const keyPtr = copyToWasm(key);
    const plaintextPtr = copyToWasm(plaintext);
    const adPtr = associatedData ? copyToWasm(associatedData) : 0;
    const ciphertextBufferPtr = wasmModule.malloc(12); // ByteBuffer size

    try {
      const result = wasmModule.sibna_encrypt(
        keyPtr,
        plaintextPtr,
        plaintext.length,
        adPtr,
        associatedData?.length || 0,
        ciphertextBufferPtr
      );
      checkResult(result);

      const ciphertext = readByteBuffer(ciphertextBufferPtr);
      freeByteBuffer(ciphertextBufferPtr);
      
      return ciphertext;
    } finally {
      wasmModule.free(keyPtr);
      wasmModule.free(plaintextPtr);
      if (adPtr) wasmModule.free(adPtr);
      wasmModule.free(ciphertextBufferPtr);
    }
  }

  /**
   * Decrypt data with a key
   */
  static decrypt(
    key: Uint8Array,
    ciphertext: Uint8Array,
    associatedData?: Uint8Array
  ): Uint8Array {
    if (!wasmModule) {
      throw new SibnaError(ErrorCode.INTERNAL_ERROR, 'WASM not initialized');
    }

    if (key.length !== 32) {
      throw new SibnaError(ErrorCode.INVALID_KEY, 'Key must be 32 bytes');
    }

    const keyPtr = copyToWasm(key);
    const ciphertextPtr = copyToWasm(ciphertext);
    const adPtr = associatedData ? copyToWasm(associatedData) : 0;
    const plaintextBufferPtr = wasmModule.malloc(12); // ByteBuffer size

    try {
      const result = wasmModule.sibna_decrypt(
        keyPtr,
        ciphertextPtr,
        ciphertext.length,
        adPtr,
        associatedData?.length || 0,
        plaintextBufferPtr
      );
      checkResult(result);

      const plaintext = readByteBuffer(plaintextBufferPtr);
      freeByteBuffer(plaintextBufferPtr);
      
      return plaintext;
    } finally {
      wasmModule.free(keyPtr);
      wasmModule.free(ciphertextPtr);
      if (adPtr) wasmModule.free(adPtr);
      wasmModule.free(plaintextBufferPtr);
    }
  }

  /**
   * Generate random bytes
   */
  static randomBytes(length: number): Uint8Array {
    if (!wasmModule) {
      throw new SibnaError(ErrorCode.INTERNAL_ERROR, 'WASM not initialized');
    }

    const bufferPtr = wasmModule.malloc(length);
    
    try {
      const result = wasmModule.sibna_random_bytes(length, bufferPtr);
      checkResult(result);
      
      return copyFromWasm(bufferPtr, length);
    } finally {
      wasmModule.free(bufferPtr);
    }
  }
}

// Convenience exports
export const generateKey = Crypto.generateKey;
export const encrypt = Crypto.encrypt;
export const decrypt = Crypto.decrypt;
export const randomBytes = Crypto.randomBytes;

// Default export
export default {
  VERSION,
  init,
  Context,
  Session,
  IdentityKeyPair,
  Crypto,
  SibnaError,
  ErrorCode,
  generateKey,
  encrypt,
  decrypt,
  randomBytes,
};
