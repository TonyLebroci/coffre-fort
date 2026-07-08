// db.js — accès IndexedDB. Toutes les données sensibles qui transitent ici
// sont déjà chiffrées (voir crypto.js) ; cette couche ne fait que persister
// des octets, sans jamais les interpréter.

const DB_NAME = 'coffre-fort-db';
const DB_VERSION = 1;

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta', { keyPath: 'key' });
      if (!db.objectStoreNames.contains('folders')) db.createObjectStore('folders', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('items')) {
        const store = db.createObjectStore('items', { keyPath: 'id' });
        store.createIndex('folderId', 'folderId');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function reqToPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function txDone(t) {
  return new Promise((resolve, reject) => {
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

export async function getMeta(key) {
  const db = await openDb();
  return reqToPromise(db.transaction('meta', 'readonly').objectStore('meta').get(key));
}

export async function putMeta(record) {
  const db = await openDb();
  const t = db.transaction('meta', 'readwrite');
  t.objectStore('meta').put(record);
  await txDone(t);
}

export async function getAllFolders() {
  const db = await openDb();
  return reqToPromise(db.transaction('folders', 'readonly').objectStore('folders').getAll());
}

export async function putFolder(folder) {
  const db = await openDb();
  const t = db.transaction('folders', 'readwrite');
  t.objectStore('folders').put(folder);
  await txDone(t);
}

export async function deleteFolder(id) {
  const db = await openDb();
  const t = db.transaction('folders', 'readwrite');
  t.objectStore('folders').delete(id);
  await txDone(t);
}

export async function getAllItems() {
  const db = await openDb();
  return reqToPromise(db.transaction('items', 'readonly').objectStore('items').getAll());
}

export async function putItem(item) {
  const db = await openDb();
  const t = db.transaction('items', 'readwrite');
  t.objectStore('items').put(item);
  await txDone(t);
}

export async function deleteItem(id) {
  const db = await openDb();
  const t = db.transaction('items', 'readwrite');
  t.objectStore('items').delete(id);
  await txDone(t);
}

// Réaffecte tous les items d'un dossier supprimé vers "Non classé" (null).
export async function reassignFolder(oldFolderId, newFolderId) {
  const db = await openDb();
  const t = db.transaction('items', 'readwrite');
  const idx = t.objectStore('items').index('folderId');
  const cursorReq = idx.openCursor(IDBKeyRange.only(oldFolderId));
  await new Promise((resolve, reject) => {
    cursorReq.onsuccess = () => {
      const cursor = cursorReq.result;
      if (cursor) {
        const val = cursor.value;
        val.folderId = newFolderId;
        cursor.update(val);
        cursor.continue();
      } else {
        resolve();
      }
    };
    cursorReq.onerror = () => reject(cursorReq.error);
  });
  await txDone(t);
}
