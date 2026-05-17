import { describe, expect, it, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import { DbClient } from "./db-client.js";

function createStoragePolyfill(): Storage {
  const store = new Map<string, string>();
  return {
    get length() {
      return store.size;
    },
    clear() {
      store.clear();
    },
    getItem(key: string) {
      return store.has(key) ? store.get(key)! : null;
    },
    key(index: number) {
      return Array.from(store.keys())[index] ?? null;
    },
    removeItem(key: string) {
      store.delete(key);
    },
    setItem(key: string, value: string) {
      store.set(key, value);
    },
  } as unknown as Storage;
}

if (typeof globalThis.localStorage === "undefined") {
  (globalThis as unknown as { localStorage: Storage }).localStorage = createStoragePolyfill();
}

describe("encryptLocalDB", () => {
  beforeEach(() => {
    globalThis.localStorage.clear();
  });

  it("stores encrypted records in IndexedDB and decrypts transparently", async () => {
    const db = new DbClient({ appId: `encrypt-test-${Math.random().toString(36).slice(2)}`, security: { encryptLocalDB: true } });
    const todos = db.collection<{ text: string; done: boolean }>("todos");

    const insertResult = await todos.insert({ text: "secret note", done: false });
    expect(insertResult.id).toBeDefined();

    const decrypted = await todos.findById(insertResult.id);
    expect(decrypted).toEqual(expect.objectContaining({ text: "secret note", done: false }));

    const rawTable = (db as any).dexie.table("todos");
    const rawRecord = await rawTable.get(insertResult.id);
    expect(rawRecord).toMatchObject({ __encrypted: true, iv: expect.any(String), ciphertext: expect.any(String) });
    expect(rawRecord.text).toBeUndefined();

    const snapshot = await db.exportSnapshot();
    expect(snapshot.collections.todos[0]).toEqual(expect.objectContaining({ text: "secret note", done: false }));

    await db.dispose();
  });
});
