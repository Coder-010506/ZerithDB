import { describe, expect, it } from "vitest";
import "fake-indexeddb/auto";
import { DbClient } from "./db-client.js";

type RawRecord = {
  _id: string;
  _createdAt: number;
  _updatedAt: number;
  text?: string;
  encryptedPayload?: string;
};

function openRawRecords(appId: string, storeName: string): Promise<RawRecord[]> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(`zerithdb_${appId}`);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const transaction = db.transaction(storeName, "readonly");
      const store = transaction.objectStore(storeName);
      const recordsRequest = store.getAll();
      recordsRequest.onerror = () => reject(recordsRequest.error);
      recordsRequest.onsuccess = () => {
        resolve(recordsRequest.result as RawRecord[]);
        db.close();
      };
    };
  });
}

describe("Local DB encryption", () => {
  it("encrypts local records at rest when enabled", async () => {
    const appId = `encrypt-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const db = new DbClient({ appId, security: { encryptLocalDB: true } });
    const todos = db.collection<{ text: string }>("todos");

    await todos.insert({ text: "secret" });

    const raw = await openRawRecords(appId, "todos");
    expect(raw).toHaveLength(1);
    expect(raw[0].text).toBeUndefined();
    expect(typeof raw[0].encryptedPayload).toBe("string");

    const result = await todos.find({});
    expect(result).toHaveLength(1);
    expect(result[0].text).toBe("secret");

    await db.dispose();
  });

  it("stores plain IndexedDB records when encryption is disabled", async () => {
    const appId = `plain-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const db = new DbClient({ appId, security: { encryptLocalDB: false } });
    const todos = db.collection<{ text: string }>("todos");

    await todos.insert({ text: "visible" });

    const raw = await openRawRecords(appId, "todos");
    expect(raw).toHaveLength(1);
    expect(raw[0].text).toBe("visible");
    expect(raw[0].encryptedPayload).toBeUndefined();

    await db.dispose();
  });
});
