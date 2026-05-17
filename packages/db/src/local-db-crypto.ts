const STORAGE_KEY_PREFIX = "__zerithdb_localdb_key_";
const ENCRYPTION_VERSION = "v1";
const IV_LENGTH = 12;

function getStorageKey(appId: string): string {
  return `${STORAGE_KEY_PREFIX}${appId}`;
}

function encodeBase64(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes = buffer instanceof ArrayBuffer
    ? new Uint8Array(buffer)
    : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return globalThis.btoa(binary);
}

function decodeBase64(value: string): Uint8Array {
  const binary = globalThis.atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function getStorage(): Storage {
  if (typeof globalThis.localStorage === "undefined") {
    throw new Error("Local storage is unavailable for local DB encryption key management.");
  }
  return globalThis.localStorage;
}

async function importKey(rawKey: Uint8Array): Promise<CryptoKey> {
  const keyData = rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength) as ArrayBuffer;
  return await globalThis.crypto.subtle.importKey(
    "raw",
    keyData,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );
}

async function exportKey(key: CryptoKey): Promise<Uint8Array> {
  const raw = await globalThis.crypto.subtle.exportKey("raw", key);
  return new Uint8Array(raw);
}

async function generateKey(): Promise<CryptoKey> {
  return await globalThis.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export class LocalDbCrypto {
  private readonly keyPromise: Promise<CryptoKey>;

  constructor(private readonly appId: string) {
    if (typeof globalThis.crypto === "undefined" || typeof globalThis.crypto.subtle === "undefined") {
      throw new Error("Browser crypto support is required for local DB encryption.");
    }
    this.keyPromise = this.loadOrCreateKey();
  }

  async encrypt<T extends Record<string, any>>(payload: T): Promise<string> {
    const key = await this.keyPromise;
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const encoded = new TextEncoder().encode(JSON.stringify(payload));
    const ivBuffer = iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer;
    const encrypted = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: ivBuffer },
      key,
      encoded
    );

    return `${ENCRYPTION_VERSION}:${encodeBase64(iv)}:${encodeBase64(encrypted)}`;
  }

  async decrypt<T extends Record<string, any>>(value: string): Promise<T> {
    const parts = value.split(":");
    if (parts.length !== 3 || parts[0] !== ENCRYPTION_VERSION) {
      throw new Error("Unsupported encrypted local DB payload format.");
    }

    const iv = decodeBase64(parts[1]);
    const ciphertext = decodeBase64(parts[2]);
    const key = await this.keyPromise;

    const ivBuffer = iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer;
    const cipherBuffer = ciphertext.buffer.slice(
      ciphertext.byteOffset,
      ciphertext.byteOffset + ciphertext.byteLength
    ) as ArrayBuffer;

    const decrypted = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBuffer },
      key,
      cipherBuffer
    );

    return JSON.parse(new TextDecoder().decode(new Uint8Array(decrypted))) as T;
  }

  private async loadOrCreateKey(): Promise<CryptoKey> {
    const storage = getStorage();
    const stored = storage.getItem(getStorageKey(this.appId));

    if (stored) {
      return importKey(decodeBase64(stored));
    }

    const key = await generateKey();
    const rawKey = await exportKey(key);
    storage.setItem(getStorageKey(this.appId), encodeBase64(rawKey));
    return key;
  }
}
