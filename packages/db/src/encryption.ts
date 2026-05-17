import type { Document } from "zerithdb-core";

const STORAGE_KEY_PREFIX = "__zerithdb_encrypt_key_";
const ENCRYPTION_VERSION = 1;
const AES_ALGORITHM = "AES-GCM";
const IV_LENGTH = 12;

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return typeof globalThis.btoa === "function"
    ? globalThis.btoa(binary)
    : Buffer.from(bytes).toString("base64");
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = typeof globalThis.atob === "function"
    ? globalThis.atob(base64)
    : Buffer.from(base64, "base64").toString("binary");
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function getStorage(): Storage | null {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem("__zerithdb_encrypt_key_check", "1");
      localStorage.removeItem("__zerithdb_encrypt_key_check");
      return localStorage;
    }
  } catch {
    // ignored
  }

  try {
    if (typeof sessionStorage !== "undefined") {
      sessionStorage.setItem("__zerithdb_encrypt_key_check", "1");
      sessionStorage.removeItem("__zerithdb_encrypt_key_check");
      return sessionStorage;
    }
  } catch {
    // ignored
  }

  return null;
}

function assertCryptoSupported(): void {
  if (typeof crypto === "undefined" || typeof crypto.subtle === "undefined") {
    throw new Error("Web Crypto is unavailable in this environment. encryptLocalDB requires crypto.subtle.");
  }
}

async function importAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new Uint8Array(rawKey).buffer as ArrayBuffer,
    AES_ALGORITHM,
    true,
    ["encrypt", "decrypt"]
  );
}

async function exportAesKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

async function generateAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    {
      name: AES_ALGORITHM,
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

function storageKey(appId: string): string {
  return `${STORAGE_KEY_PREFIX}${appId}`;
}

export class LocalDbEncryption {
  private key: CryptoKey | null = null;
  private storage: Storage | null = null;

  constructor(private readonly appId: string) {}

  async init(): Promise<void> {
    assertCryptoSupported();
    const storage = getStorage();
    if (!storage) {
      throw new Error(
        "Unable to persist local encryption key. encryptLocalDB requires localStorage or sessionStorage."
      );
    }

    this.storage = storage;
    const storedKey = storage.getItem(storageKey(this.appId));
    if (storedKey) {
      const rawKey = base64ToBytes(storedKey);
      this.key = await importAesKey(rawKey);
      return;
    }

    const key = await generateAesKey();
    const exported = await exportAesKey(key);
    storage.setItem(storageKey(this.appId), bytesToBase64(exported));
    this.key = key;
  }

  async encrypt<T extends Record<string, any>>(document: Document<T>): Promise<Record<string, any>> {
    if (!this.key) {
      throw new Error("Local DB encryption manager is not initialized.");
    }

    const { _id, _createdAt, _updatedAt, ...payload } = document as Document<T> & {
      _id: string;
      _createdAt: number;
      _updatedAt: number;
    };
    const plaintext = JSON.stringify(payload);
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const ciphertext = await crypto.subtle.encrypt(
      { name: AES_ALGORITHM, iv: iv.buffer as ArrayBuffer },
      this.key,
      new TextEncoder().encode(plaintext)
    );

    return {
      _id,
      _createdAt,
      _updatedAt,
      __encrypted: true,
      __encryptionVersion: ENCRYPTION_VERSION,
      iv: bytesToBase64(new Uint8Array(iv)),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    };
  }

  async decrypt<T extends Record<string, any>>(record: Record<string, any>): Promise<Document<T>> {
    if (!record?.__encrypted) {
      return record as Document<T>;
    }

    if (!this.key) {
      throw new Error("Local DB encryption manager is not initialized.");
    }

    if (record.__encryptionVersion !== ENCRYPTION_VERSION) {
      throw new Error("Unsupported local DB encryption version.");
    }

    const iv = base64ToBytes(record.iv as string);
    const ciphertext = base64ToBytes(record.ciphertext as string);
    const plaintextBytes = await crypto.subtle.decrypt(
      { name: AES_ALGORITHM, iv: iv.buffer as ArrayBuffer },
      this.key,
      ciphertext.buffer as ArrayBuffer
    );
    const payloadJson = new TextDecoder().decode(plaintextBytes);
    const payload = JSON.parse(payloadJson) as Record<string, any>;

    return {
      ...payload,
      _id: record._id,
      _createdAt: record._createdAt,
      _updatedAt: record._updatedAt,
    } as Document<T>;
  }
}
