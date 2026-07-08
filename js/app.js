import * as db from './db.js';
import * as wa from './crypto.js';

// ---------------------------------------------------------------------------
// État en mémoire. state.vaultKey ne vit jamais ailleurs qu'ici : il est
// effacé au verrouillage et n'est jamais persisté en clair.
// ---------------------------------------------------------------------------
const state = {
  vaultKey: null,
  meta: null,
  folders: [],
  items: [],
  currentFolderId: 'all',
  searchQuery: '',
  thumbCache: new Map(), // itemId -> object URL
};

let currentViewerItemId = null;
let currentViewerFace = 'front'; // 'front' | 'back'
let currentPasswordItemId = null;
let editingFolderId = null;
let pendingDoc = { front: null, verso: null };

const dateFormatter = new Intl.DateTimeFormat('fr-FR', { day: 'numeric', month: 'short', year: 'numeric' });
const formatDate = (ts) => dateFormatter.format(new Date(ts));

const $ = (id) => document.getElementById(id);

function showScreen(name) {
  for (const id of ['screen-loading', 'screen-unsupported', 'screen-setup', 'screen-lock', 'screen-main']) {
    $(id).hidden = id !== `screen-${name}`;
  }
}

function showToast(msg, ms = 3000) {
  const el = $('toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => { el.hidden = true; }, ms);
}

function friendlyError(err) {
  if (!err) return 'Erreur inconnue.';
  if (err.name === 'NotAllowedError') return 'Authentification annulée, refusée, ou clé introuvable sur cet appareil.';
  if (err.name === 'InvalidStateError') return 'Un passkey existe déjà pour cet appareil.';
  if (err.name === 'OperationError') return 'Clé incorrecte.';
  return (err.name ? err.name + ' : ' : '') + (err.message || 'Erreur inconnue.');
}

// ---------------------------------------------------------------------------
// Démarrage
// ---------------------------------------------------------------------------
async function boot() {
  showScreen('loading');
  if (!window.isSecureContext || !window.PublicKeyCredential) {
    $('unsupported-message').textContent =
      "Cette page doit être servie en HTTPS (ou localhost) avec un navigateur compatible WebAuthn pour fonctionner.";
    showScreen('unsupported');
    return;
  }
  const platformOk = await wa.isPlatformAuthenticatorAvailable();
  const meta = await db.getMeta('vault');
  if (!meta) {
    if (!platformOk) {
      $('unsupported-message').textContent =
        "Aucun capteur biométrique (Face ID, Touch ID, Windows Hello…) n'a été détecté sur cet appareil.";
      showScreen('unsupported');
      return;
    }
    showScreen('setup');
    return;
  }
  state.meta = meta;
  $('lock-hint').textContent = meta.mode === 'passphrase' ? 'Face ID / Touch ID, puis ta phrase secrète.' : '';
  showScreen('lock');
}

// ---------------------------------------------------------------------------
// Création du coffre
// ---------------------------------------------------------------------------
$('btn-start-setup').addEventListener('click', async () => {
  const btn = $('btn-start-setup');
  btn.disabled = true;
  try {
    const { rawId } = await wa.createPasskey();
    const prfSalt = wa.randomBytes(32);
    let secret = null;
    try {
      secret = await wa.getPrfSecret(rawId, prfSalt);
    } catch (err) {
      console.warn('Sondage PRF échoué', err);
    }
    const vaultKey = await wa.generateVaultKey();
    let mode;
    let wrappingKey;
    let pbkdf2Salt = null;
    if (secret) {
      mode = 'prf';
      wrappingKey = await wa.deriveWrappingKeyFromPrf(secret);
    } else {
      mode = 'passphrase';
      const passphrase = await promptPassphrase('new');
      if (!passphrase) { btn.disabled = false; return; }
      pbkdf2Salt = wa.randomBytes(16);
      wrappingKey = await wa.deriveKeyFromPassphrase(passphrase, pbkdf2Salt);
    }
    const { wrapped, iv } = await wa.wrapVaultKey(vaultKey, wrappingKey);
    const metaRecord = { key: 'vault', rawId, prfSalt, mode, pbkdf2Salt, wrapped, iv, createdAt: Date.now() };
    await db.putMeta(metaRecord);
    state.meta = metaRecord;
    state.vaultKey = vaultKey;
    await loadVaultData();
    showScreen('main');
    resetInactivityTimer();
    showToast('Coffre-fort créé.');
  } catch (err) {
    console.error(err);
    showToast('Échec de la création : ' + friendlyError(err));
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// Déverrouillage
// ---------------------------------------------------------------------------
$('btn-unlock').addEventListener('click', async () => {
  const btn = $('btn-unlock');
  btn.disabled = true;
  try {
    const meta = state.meta || await db.getMeta('vault');
    if (!meta) { showScreen('setup'); return; }
    let wrappingKey;
    if (meta.mode === 'prf') {
      const secret = await wa.getPrfSecret(meta.rawId, meta.prfSalt);
      if (!secret) throw new Error('PRF_UNAVAILABLE');
      wrappingKey = await wa.deriveWrappingKeyFromPrf(secret);
    } else {
      await wa.assertPresenceOnly(meta.rawId);
      const passphrase = await promptPassphrase('unlock');
      if (!passphrase) return;
      wrappingKey = await wa.deriveKeyFromPassphrase(passphrase, meta.pbkdf2Salt);
    }
    const vaultKey = await wa.unwrapVaultKey(meta.wrapped, meta.iv, wrappingKey);
    state.vaultKey = vaultKey;
    state.meta = meta;
    await loadVaultData();
    showScreen('main');
    resetInactivityTimer();
  } catch (err) {
    console.error(err);
    showToast(err.message === 'PRF_UNAVAILABLE' ? 'Impossible de dériver la clé sur cet appareil.' : friendlyError(err));
  } finally {
    btn.disabled = false;
  }
});

// Filet de sécurité : si le passkey d'origine devient inutilisable (perdu,
// non reconnu par l'appareil, etc.), il n'existe aucun autre moyen de
// déchiffrer le coffre — mais l'utilisateur doit pouvoir recommencer plutôt
// que de rester bloqué indéfiniment sur l'écran de verrouillage.
$('btn-reset-vault').addEventListener('click', async () => {
  const ok = await confirmDialog(
    'Réinitialiser supprime définitivement tous les documents et mots de passe stockés sur cet appareil ' +
    '(aucune sauvegarde n\'existe ailleurs). À utiliser seulement si Face ID / Touch ID ne parvient plus ' +
    'du tout à déverrouiller le coffre. Continuer ?'
  );
  if (!ok) return;
  try {
    await db.clearAll();
    state.vaultKey = null;
    state.meta = null;
    state.folders = [];
    state.items = [];
    for (const url of state.thumbCache.values()) URL.revokeObjectURL(url);
    state.thumbCache.clear();
    showToast('Coffre-fort réinitialisé.');
    showScreen('setup');
  } catch (err) {
    console.error(err);
    showToast('La réinitialisation a échoué : ' + friendlyError(err));
  }
});

// ---------------------------------------------------------------------------
// Verrouillage manuel / automatique
// ---------------------------------------------------------------------------
function lockVault() {
  state.vaultKey = null; // toute opération de chiffrement en attente est abandonnée, pas persistée en clair
  document.querySelectorAll('dialog[open]').forEach((d) => d.close());
  state.items = [];
  state.folders = [];
  for (const url of state.thumbCache.values()) URL.revokeObjectURL(url);
  state.thumbCache.clear();
  $('item-list').innerHTML = '';
  $('folder-chips').innerHTML = '';
  $('search-input').value = '';
  state.searchQuery = '';
  $('lock-hint').textContent = state.meta && state.meta.mode === 'passphrase' ? 'Face ID / Touch ID, puis ta phrase secrète.' : '';
  showScreen('lock');
}
$('btn-lock').addEventListener('click', lockVault);

const LOCK_AFTER_MS = 3 * 60 * 1000;
let inactivityTimer = null;
function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  if (state.vaultKey) inactivityTimer = setTimeout(lockVault, LOCK_AFTER_MS);
}
['pointerdown', 'keydown', 'touchstart', 'wheel', 'scroll'].forEach((evt) =>
  document.addEventListener(evt, () => { if (state.vaultKey) resetInactivityTimer(); }, { passive: true })
);
document.addEventListener('visibilitychange', () => {
  if (document.hidden && state.vaultKey) lockVault();
});

// ---------------------------------------------------------------------------
// Chargement / déchiffrement des métadonnées après déverrouillage
// ---------------------------------------------------------------------------
async function loadVaultData() {
  const folderRecords = await db.getAllFolders();
  state.folders = [];
  for (const f of folderRecords) {
    try {
      const data = await wa.decryptJson(state.vaultKey, f.iv, f.nameCipher);
      state.folders.push({ id: f.id, name: data.name, createdAt: f.createdAt });
    } catch (err) { console.error('Dossier illisible', f.id, err); }
  }
  const itemRecords = await db.getAllItems();
  state.items = [];
  for (const it of itemRecords) {
    try {
      const data = await wa.decryptJson(state.vaultKey, it.metaIv, it.metaCipher);
      state.items.push({
        id: it.id, folderId: it.folderId, type: it.type, deletedAt: it.deletedAt || null,
        createdAt: it.createdAt, updatedAt: it.updatedAt, mimeType: it.mimeType,
        ...data, _record: it,
      });
    } catch (err) { console.error('Élément illisible', it.id, err); }
  }

  // Purge silencieuse des éléments à la corbeille depuis plus de 30 jours.
  const TRASH_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  const expired = state.items.filter((i) => i.deletedAt && now - i.deletedAt > TRASH_RETENTION_MS);
  for (const item of expired) {
    await db.deleteItem(item.id);
  }
  if (expired.length) {
    const expiredIds = new Set(expired.map((i) => i.id));
    state.items = state.items.filter((i) => !expiredIds.has(i.id));
  }

  state.currentFolderId = 'all';
  state.searchQuery = '';
  $('search-input').value = '';
  renderFolders();
  renderItems();
}

// ---------------------------------------------------------------------------
// Rendu — dossiers
// ---------------------------------------------------------------------------
function renderFolders() {
  const container = $('folder-chips');
  container.innerHTML = '';
  const activeItems = state.items.filter((i) => !i.deletedAt);
  const trashCount = state.items.length - activeItems.length;
  const counts = new Map();
  for (const it of activeItems) {
    const key = it.folderId || 'unfiled';
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const chipsData = [
    { id: 'all', name: 'Tous', count: activeItems.length },
    { id: 'unfiled', name: 'Non classé', count: counts.get('unfiled') || 0 },
    ...state.folders.slice().sort((a, b) => a.name.localeCompare(b.name, 'fr'))
      .map((f) => ({ id: f.id, name: f.name, count: counts.get(f.id) || 0 })),
  ];
  for (const c of chipsData) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'chip' + (state.currentFolderId === c.id ? ' active' : '');
    btn.textContent = `${c.name} (${c.count})`;
    btn.addEventListener('click', () => {
      state.currentFolderId = c.id;
      renderFolders();
      renderItems();
    });
    container.appendChild(btn);
    if (c.id !== 'all' && c.id !== 'unfiled' && state.currentFolderId === c.id) {
      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'chip';
      editBtn.title = 'Modifier ce dossier';
      editBtn.textContent = '✎';
      editBtn.addEventListener('click', () => openFolderDialog(c.id));
      container.appendChild(editBtn);
    }
  }
  const newBtn = document.createElement('button');
  newBtn.type = 'button';
  newBtn.className = 'chip chip-new';
  newBtn.textContent = '+ Dossier';
  newBtn.addEventListener('click', () => openFolderDialog(null));
  container.appendChild(newBtn);

  const trashBtn = document.createElement('button');
  trashBtn.type = 'button';
  trashBtn.className = 'chip chip-trash' + (state.currentFolderId === 'trash' ? ' active' : '');
  trashBtn.textContent = `🗑️ Corbeille (${trashCount})`;
  trashBtn.addEventListener('click', () => {
    state.currentFolderId = 'trash';
    renderFolders();
    renderItems();
  });
  container.appendChild(trashBtn);

  $('btn-add').hidden = state.currentFolderId === 'trash';
}

function populateFolderSelect(select, currentValue) {
  select.innerHTML = '';
  const unfiledOpt = document.createElement('option');
  unfiledOpt.value = '';
  unfiledOpt.textContent = 'Non classé';
  select.appendChild(unfiledOpt);
  for (const f of state.folders.slice().sort((a, b) => a.name.localeCompare(b.name, 'fr'))) {
    const opt = document.createElement('option');
    opt.value = f.id;
    opt.textContent = f.name;
    select.appendChild(opt);
  }
  select.value = (!currentValue || currentValue === 'all' || currentValue === 'unfiled') ? '' : currentValue;
}

function openFolderDialog(folderId) {
  editingFolderId = folderId;
  const input = $('folder-name-input');
  if (folderId) {
    const folder = state.folders.find((f) => f.id === folderId);
    $('folder-dialog-title').textContent = 'Modifier le dossier';
    input.value = folder ? folder.name : '';
    $('folder-delete').hidden = false;
  } else {
    $('folder-dialog-title').textContent = 'Nouveau dossier';
    input.value = '';
    $('folder-delete').hidden = true;
  }
  $('dialog-folder').showModal();
  input.focus();
}
$('folder-close').addEventListener('click', () => $('dialog-folder').close());
$('dialog-folder').addEventListener('close', () => { editingFolderId = null; });

$('form-folder').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('folder-name-input').value.trim();
  if (!name) return;
  if (editingFolderId) {
    const folder = state.folders.find((f) => f.id === editingFolderId);
    const { iv, cipher } = await wa.encryptJson(state.vaultKey, { name });
    await db.putFolder({ id: editingFolderId, createdAt: folder.createdAt, iv, nameCipher: cipher });
    folder.name = name;
  } else {
    const id = crypto.randomUUID();
    const now = Date.now();
    const { iv, cipher } = await wa.encryptJson(state.vaultKey, { name });
    await db.putFolder({ id, createdAt: now, iv, nameCipher: cipher });
    state.folders.push({ id, name, createdAt: now });
    state.currentFolderId = id;
  }
  $('dialog-folder').close();
  renderFolders();
  renderItems();
});

$('folder-delete').addEventListener('click', async () => {
  if (!editingFolderId) return;
  const ok = await confirmDialog('Supprimer ce dossier ? Les éléments qu\'il contient seront déplacés vers "Non classé".');
  if (!ok) return;
  const id = editingFolderId;
  await db.reassignFolder(id, null);
  await db.deleteFolder(id);
  state.items.forEach((it) => { if (it.folderId === id) it.folderId = null; });
  state.folders = state.folders.filter((f) => f.id !== id);
  if (state.currentFolderId === id) state.currentFolderId = 'all';
  $('dialog-folder').close();
  renderFolders();
  renderItems();
});

// ---------------------------------------------------------------------------
// Rendu — liste des éléments + recherche
// ---------------------------------------------------------------------------
function filteredItems() {
  const q = state.searchQuery.trim().toLowerCase();
  const matchesQuery = (i) => {
    if (!q) return true;
    const folderName = i.folderId ? (state.folders.find((f) => f.id === i.folderId)?.name || '') : 'non classé';
    const hay = [i.title, i.username, folderName].filter(Boolean).join(' ').toLowerCase();
    return hay.includes(q);
  };

  if (state.currentFolderId === 'trash') {
    return state.items.filter((i) => i.deletedAt && matchesQuery(i))
      .sort((a, b) => b.deletedAt - a.deletedAt);
  }

  let list = state.items.filter((i) => !i.deletedAt);
  if (q) {
    list = list.filter(matchesQuery);
  } else if (state.currentFolderId === 'unfiled') {
    list = list.filter((i) => !i.folderId);
  } else if (state.currentFolderId !== 'all') {
    list = list.filter((i) => i.folderId === state.currentFolderId);
  }
  return list.slice().sort((a, b) => b.updatedAt - a.updatedAt);
}

function renderItems() {
  const list = filteredItems();
  const container = $('item-list');
  const empty = $('empty-state');
  container.innerHTML = '';
  if (list.length === 0) {
    empty.hidden = false;
    if (state.currentFolderId === 'trash') {
      $('empty-text').textContent = 'La corbeille est vide.';
    } else {
      $('empty-text').innerHTML = state.searchQuery.trim()
        ? 'Aucun résultat pour cette recherche.'
        : 'Aucun document pour l\'instant.<br/>Appuie sur + pour ajouter ta première carte.';
    }
    return;
  }
  empty.hidden = true;
  for (const item of list) {
    container.appendChild(item.deletedAt ? renderTrashCard(item) : renderItemCard(item));
  }
}

function renderTrashCard(item) {
  const card = document.createElement('div');
  card.className = 'item-card trash-card';

  const thumb = document.createElement('div');
  thumb.className = 'item-thumb';
  thumb.textContent = item.type === 'password' ? '🔑' : '📄';
  card.appendChild(thumb);

  const info = document.createElement('div');
  info.className = 'item-info';
  const title = document.createElement('div');
  title.className = 'item-title';
  title.textContent = item.title || '(Sans titre)';
  const sub = document.createElement('div');
  sub.className = 'item-sub';
  sub.textContent = `Supprimé le ${formatDate(item.deletedAt)}`;
  info.append(title, sub);
  card.appendChild(info);

  const actions = document.createElement('div');
  actions.className = 'trash-actions';
  const restoreBtn = document.createElement('button');
  restoreBtn.type = 'button';
  restoreBtn.textContent = 'Restaurer';
  restoreBtn.addEventListener('click', () => restoreItem(item.id));
  const purgeBtn = document.createElement('button');
  purgeBtn.type = 'button';
  purgeBtn.className = 'btn-purge';
  purgeBtn.textContent = 'Supprimer déf.';
  purgeBtn.addEventListener('click', () => purgeItem(item.id));
  actions.append(restoreBtn, purgeBtn);
  card.appendChild(actions);

  return card;
}

function renderItemCard(item) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'item-card';

  const thumb = document.createElement('div');
  thumb.className = 'item-thumb';
  thumb.textContent = item.type === 'password' ? '🔑' : '📄';
  btn.appendChild(thumb);

  const info = document.createElement('div');
  info.className = 'item-info';
  const title = document.createElement('div');
  title.className = 'item-title';
  title.textContent = item.title || '(Sans titre)';
  const sub = document.createElement('div');
  sub.className = 'item-sub';
  const folderName = item.folderId ? (state.folders.find((f) => f.id === item.folderId)?.name || 'Dossier') : 'Non classé';
  sub.textContent = `${folderName} · ${formatDate(item.updatedAt)}`;
  info.append(title, sub);
  btn.appendChild(info);

  btn.addEventListener('click', () => {
    if (item.type === 'document') openViewer(item.id);
    else openPasswordDetail(item.id);
  });

  if (item.type === 'document' && item._record.thumbCipher) {
    getThumbUrl(item).then((url) => {
      if (!url) return;
      thumb.innerHTML = `<img src="${url}" alt="" />`;
      if (item._record.backCipher) {
        const badge = document.createElement('span');
        badge.className = 'thumb-badge';
        badge.textContent = 'R/V';
        thumb.appendChild(badge);
      }
    }).catch(() => {});
  }

  return btn;
}

async function getThumbUrl(item) {
  if (state.thumbCache.has(item.id)) return state.thumbCache.get(item.id);
  const rec = item._record;
  if (!rec.thumbCipher) return null;
  const bytes = await wa.decryptBytes(state.vaultKey, rec.thumbIv, rec.thumbCipher);
  const blob = new Blob([bytes], { type: item.mimeType || 'image/jpeg' });
  const url = URL.createObjectURL(blob);
  state.thumbCache.set(item.id, url);
  return url;
}

// Suppression définitive (irréversible). N'est appelée que depuis la
// corbeille, ou lors de la purge automatique des éléments trop anciens.
async function removeItem(id) {
  await db.deleteItem(id);
  const idx = state.items.findIndex((i) => i.id === id);
  if (idx !== -1) state.items.splice(idx, 1);
  if (state.thumbCache.has(id)) {
    URL.revokeObjectURL(state.thumbCache.get(id));
    state.thumbCache.delete(id);
  }
  renderFolders();
  renderItems();
}

// Suppression « normale » : déplace vers la corbeille, récupérable.
async function moveItemToTrash(id) {
  const item = state.items.find((i) => i.id === id);
  if (!item) return;
  item._record.deletedAt = Date.now();
  await db.putItem(item._record);
  item.deletedAt = item._record.deletedAt;
  if (state.thumbCache.has(id)) {
    URL.revokeObjectURL(state.thumbCache.get(id));
    state.thumbCache.delete(id);
  }
  renderFolders();
  renderItems();
}

async function restoreItem(id) {
  const item = state.items.find((i) => i.id === id);
  if (!item) return;
  delete item._record.deletedAt;
  item._record.updatedAt = Date.now();
  await db.putItem(item._record);
  delete item.deletedAt;
  item.updatedAt = item._record.updatedAt;
  renderFolders();
  renderItems();
  showToast('Élément restauré.');
}

async function purgeItem(id) {
  const ok = await confirmDialog('Supprimer définitivement cet élément ? Cette action est irréversible.');
  if (!ok) return;
  await removeItem(id);
  showToast('Supprimé définitivement.');
}

$('btn-search-toggle').addEventListener('click', () => {
  const bar = $('search-bar');
  bar.hidden = !bar.hidden;
  if (!bar.hidden) {
    $('search-input').focus();
  } else {
    $('search-input').value = '';
    state.searchQuery = '';
    renderItems();
  }
});
$('search-input').addEventListener('input', (e) => {
  state.searchQuery = e.target.value;
  renderItems();
});

// ---------------------------------------------------------------------------
// Visionneuse plein écran (documents)
// ---------------------------------------------------------------------------
async function loadViewerFace(item, face) {
  const rec = item._record;
  const iv = face === 'back' ? rec.backIv : rec.fileIv;
  const cipher = face === 'back' ? rec.backCipher : rec.fileCipher;
  if (!cipher) return;
  const img = $('viewer-img');
  try {
    const bytes = await wa.decryptBytes(state.vaultKey, iv, cipher);
    const blob = new Blob([bytes], { type: item.mimeType || 'image/jpeg' });
    const url = URL.createObjectURL(blob);
    if (img.dataset.blobUrl) URL.revokeObjectURL(img.dataset.blobUrl);
    img.src = url;
    img.dataset.blobUrl = url;
  } catch (err) {
    console.error(err);
    showToast('Impossible d\'ouvrir cette image.');
  }
}

function updateViewerFaceUI(item) {
  const hasVerso = !!item._record.backCipher;
  $('viewer-face-bar').hidden = !hasVerso;
  $('viewer-add-verso').hidden = hasVerso;
  $('viewer-face-front').classList.toggle('active', currentViewerFace === 'front');
  $('viewer-face-verso').classList.toggle('active', currentViewerFace === 'back');
}

async function openViewer(id) {
  const item = state.items.find((i) => i.id === id);
  if (!item) return;
  currentViewerItemId = id;
  currentViewerFace = 'front';
  $('viewer-img').removeAttribute('src');
  await loadViewerFace(item, 'front');
  $('viewer-title').value = item.title;
  populateFolderSelect($('viewer-folder'), item.folderId);
  updateViewerFaceUI(item);
  $('dialog-viewer').showModal();
}

$('viewer-face-front').addEventListener('click', async () => {
  if (currentViewerFace === 'front') return;
  const item = state.items.find((i) => i.id === currentViewerItemId);
  if (!item) return;
  currentViewerFace = 'front';
  await loadViewerFace(item, 'front');
  updateViewerFaceUI(item);
});
$('viewer-face-verso').addEventListener('click', async () => {
  if (currentViewerFace === 'back') return;
  const item = state.items.find((i) => i.id === currentViewerItemId);
  if (!item) return;
  currentViewerFace = 'back';
  await loadViewerFace(item, 'back');
  updateViewerFaceUI(item);
});

$('viewer-verso-remove').addEventListener('click', async () => {
  const item = state.items.find((i) => i.id === currentViewerItemId);
  if (!item) return;
  const ok = await confirmDialog('Supprimer la photo du verso ?');
  if (!ok) return;
  const rec = item._record;
  delete rec.backIv;
  delete rec.backCipher;
  delete rec.backThumbIv;
  delete rec.backThumbCipher;
  rec.updatedAt = Date.now();
  await db.putItem(rec);
  item.updatedAt = rec.updatedAt;
  currentViewerFace = 'front';
  await loadViewerFace(item, 'front');
  updateViewerFaceUI(item);
  renderItems();
  showToast('Verso supprimé.');
});

$('viewer-add-verso').addEventListener('click', () => $('viewer-verso-input').click());
$('viewer-verso-input').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const item = state.items.find((i) => i.id === currentViewerItemId);
  if (!item) { e.target.value = ''; return; }
  try {
    const bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
    const fullBlob = await drawToCanvasBlob(bitmap, 1600, 0.85);
    const thumbBlob = await drawToCanvasBlob(bitmap, 220, 0.7);
    const fullBytes = new Uint8Array(await fullBlob.arrayBuffer());
    const thumbBytes = new Uint8Array(await thumbBlob.arrayBuffer());
    const { iv: backIv, cipher: backCipher } = await wa.encryptBytes(state.vaultKey, fullBytes);
    const { iv: backThumbIv, cipher: backThumbCipher } = await wa.encryptBytes(state.vaultKey, thumbBytes);
    const rec = item._record;
    rec.backIv = backIv;
    rec.backCipher = backCipher;
    rec.backThumbIv = backThumbIv;
    rec.backThumbCipher = backThumbCipher;
    rec.updatedAt = Date.now();
    await db.putItem(rec);
    item.updatedAt = rec.updatedAt;
    currentViewerFace = 'back';
    await loadViewerFace(item, 'back');
    updateViewerFaceUI(item);
    renderItems();
    showToast('Verso ajouté.');
  } catch (err) {
    console.error(err);
    showToast('Impossible de lire cette image.');
  } finally {
    e.target.value = '';
  }
});

async function saveViewerChangesIfNeeded() {
  if (!state.vaultKey) return;
  const item = state.items.find((i) => i.id === currentViewerItemId);
  if (!item) return;
  const newTitle = $('viewer-title').value.trim() || '(Sans titre)';
  const newFolderId = $('viewer-folder').value || null;
  if (newTitle === item.title && newFolderId === item.folderId) return;
  const { iv, cipher } = await wa.encryptJson(state.vaultKey, { title: newTitle });
  item._record.metaIv = iv;
  item._record.metaCipher = cipher;
  item._record.folderId = newFolderId;
  item._record.updatedAt = Date.now();
  await db.putItem(item._record);
  item.title = newTitle;
  item.folderId = newFolderId;
  item.updatedAt = item._record.updatedAt;
  renderFolders();
  renderItems();
}

$('dialog-viewer').addEventListener('close', async () => {
  await saveViewerChangesIfNeeded();
  const img = $('viewer-img');
  if (img.dataset.blobUrl) { URL.revokeObjectURL(img.dataset.blobUrl); delete img.dataset.blobUrl; }
  img.removeAttribute('src');
  currentViewerItemId = null;
  currentViewerFace = 'front';
});
$('viewer-close').addEventListener('click', () => $('dialog-viewer').close());
$('viewer-delete').addEventListener('click', async () => {
  const id = currentViewerItemId;
  currentViewerItemId = null; // évite une tentative de sauvegarde des champs à la fermeture
  await moveItemToTrash(id);
  $('dialog-viewer').close();
  showToast('Déplacé dans la corbeille.');
});

// ---------------------------------------------------------------------------
// Détail / édition d'un mot de passe
// ---------------------------------------------------------------------------
function openPasswordDetail(id) {
  const item = state.items.find((i) => i.id === id);
  if (!item) return;
  currentPasswordItemId = id;
  $('pwd-title').value = item.title || '';
  $('pwd-username').value = item.username || '';
  $('pwd-password').value = item.password || '';
  $('pwd-password').type = 'password';
  $('pwd-notes').value = item.notes || '';
  populateFolderSelect($('pwd-folder'), item.folderId);
  $('dialog-password').showModal();
}
$('pwd-close').addEventListener('click', () => $('dialog-password').close());
$('dialog-password').addEventListener('close', () => { currentPasswordItemId = null; });
$('pwd-toggle-visibility').addEventListener('click', () => {
  const input = $('pwd-password');
  input.type = input.type === 'password' ? 'text' : 'password';
});

$('form-password-detail').addEventListener('submit', async (e) => {
  e.preventDefault();
  const item = state.items.find((i) => i.id === currentPasswordItemId);
  if (!item) return;
  const title = $('pwd-title').value.trim() || '(Sans titre)';
  const username = $('pwd-username').value.trim();
  const password = $('pwd-password').value;
  const notes = $('pwd-notes').value.trim();
  const folderId = $('pwd-folder').value || null;
  const { iv, cipher } = await wa.encryptJson(state.vaultKey, { title, username, password, notes });
  item._record.metaIv = iv;
  item._record.metaCipher = cipher;
  item._record.folderId = folderId;
  item._record.updatedAt = Date.now();
  await db.putItem(item._record);
  Object.assign(item, { title, username, password, notes, folderId, updatedAt: item._record.updatedAt });
  $('dialog-password').close();
  renderFolders();
  renderItems();
  showToast('Mot de passe enregistré.');
});

$('pwd-delete').addEventListener('click', async () => {
  const id = currentPasswordItemId;
  currentPasswordItemId = null;
  await moveItemToTrash(id);
  $('dialog-password').close();
  showToast('Déplacé dans la corbeille.');
});

// Copie dans le presse-papiers, effacée automatiquement après 20 s.
document.querySelectorAll('.btn-copy[data-copy-target]').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const target = $(btn.dataset.copyTarget);
    if (!target || !target.value) return;
    try {
      const val = target.value;
      await navigator.clipboard.writeText(val);
      showToast('Copié (effacé du presse-papiers dans 20 s).');
      setTimeout(async () => {
        try {
          const current = await navigator.clipboard.readText();
          if (current === val) await navigator.clipboard.writeText('');
        } catch { /* lecture du presse-papiers non permise, tant pis */ }
      }, 20000);
    } catch {
      showToast('Impossible de copier.');
    }
  });
});

// ---------------------------------------------------------------------------
// Ajout d'un élément
// ---------------------------------------------------------------------------
function resetAddDialog() {
  $('add-step-type').hidden = false;
  $('form-add-document').hidden = true;
  $('form-add-password').hidden = true;
  $('doc-file-input').value = '';
  const preview = $('doc-preview');
  if (preview.dataset.blobUrl) { URL.revokeObjectURL(preview.dataset.blobUrl); delete preview.dataset.blobUrl; }
  preview.removeAttribute('src');
  $('doc-preview-wrap').hidden = true;
  $('doc-verso-input').value = '';
  const versoPreview = $('doc-verso-preview');
  if (versoPreview.dataset.blobUrl) { URL.revokeObjectURL(versoPreview.dataset.blobUrl); delete versoPreview.dataset.blobUrl; }
  versoPreview.removeAttribute('src');
  $('doc-verso-preview-wrap').hidden = true;
  $('doc-verso-label').hidden = false;
  $('doc-title').value = '';
  $('doc-save').disabled = true;
  pendingDoc = { front: null, verso: null };
  $('new-pwd-title').value = '';
  $('new-pwd-username').value = '';
  $('new-pwd-password').value = '';
  $('new-pwd-password').type = 'password';
  $('new-pwd-notes').value = '';
}

$('btn-add').addEventListener('click', () => {
  resetAddDialog();
  populateFolderSelect($('doc-folder'), state.currentFolderId);
  populateFolderSelect($('new-pwd-folder'), state.currentFolderId);
  $('dialog-add').showModal();
});
$('add-close').addEventListener('click', () => $('dialog-add').close());
$('dialog-add').addEventListener('close', resetAddDialog);

$('choose-type-document').addEventListener('click', () => {
  $('add-step-type').hidden = true;
  $('form-add-document').hidden = false;
});
$('choose-type-password').addEventListener('click', () => {
  $('add-step-type').hidden = true;
  $('form-add-password').hidden = false;
});
$('doc-back').addEventListener('click', () => {
  $('form-add-document').hidden = true;
  $('add-step-type').hidden = false;
});
$('pwd-add-back').addEventListener('click', () => {
  $('form-add-password').hidden = true;
  $('add-step-type').hidden = false;
});
$('new-pwd-toggle-visibility').addEventListener('click', () => {
  const input = $('new-pwd-password');
  input.type = input.type === 'password' ? 'text' : 'password';
});

function drawToCanvasBlob(bitmap, maxDim, quality) {
  const scale = Math.min(1, maxDim / Math.max(bitmap.width, bitmap.height));
  const w = Math.max(1, Math.round(bitmap.width * scale));
  const h = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = h;
  canvas.getContext('2d').drawImage(bitmap, 0, 0, w, h);
  return new Promise((resolve, reject) => {
    canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('toBlob a échoué'))), 'image/jpeg', quality);
  });
}

$('doc-file-input').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
    const fullBlob = await drawToCanvasBlob(bitmap, 1600, 0.85);
    const thumbBlob = await drawToCanvasBlob(bitmap, 220, 0.7);
    pendingDoc.front = { fullBlob, thumbBlob };
    const preview = $('doc-preview');
    if (preview.dataset.blobUrl) URL.revokeObjectURL(preview.dataset.blobUrl);
    const previewUrl = URL.createObjectURL(fullBlob);
    preview.src = previewUrl;
    preview.dataset.blobUrl = previewUrl;
    $('doc-preview-wrap').hidden = false;
    $('doc-save').disabled = false;
    const titleField = $('doc-title');
    if (!titleField.value.trim()) titleField.value = file.name.replace(/\.[^.]+$/, '');
  } catch (err) {
    console.error(err);
    showToast('Impossible de lire cette image.');
  }
});

$('doc-verso-input').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
    const fullBlob = await drawToCanvasBlob(bitmap, 1600, 0.85);
    const thumbBlob = await drawToCanvasBlob(bitmap, 220, 0.7);
    pendingDoc.verso = { fullBlob, thumbBlob };
    const preview = $('doc-verso-preview');
    if (preview.dataset.blobUrl) URL.revokeObjectURL(preview.dataset.blobUrl);
    const previewUrl = URL.createObjectURL(fullBlob);
    preview.src = previewUrl;
    preview.dataset.blobUrl = previewUrl;
    $('doc-verso-preview-wrap').hidden = false;
    $('doc-verso-label').hidden = true;
  } catch (err) {
    console.error(err);
    showToast('Impossible de lire cette image.');
  }
});

$('doc-verso-remove').addEventListener('click', () => {
  pendingDoc.verso = null;
  const preview = $('doc-verso-preview');
  if (preview.dataset.blobUrl) { URL.revokeObjectURL(preview.dataset.blobUrl); delete preview.dataset.blobUrl; }
  preview.removeAttribute('src');
  $('doc-verso-preview-wrap').hidden = true;
  $('doc-verso-label').hidden = false;
  $('doc-verso-input').value = '';
});

async function saveNewDocument({ front, verso, title, folderId }) {
  const mimeType = 'image/jpeg';
  const frontFullBytes = new Uint8Array(await front.fullBlob.arrayBuffer());
  const frontThumbBytes = new Uint8Array(await front.thumbBlob.arrayBuffer());
  const { iv: fileIv, cipher: fileCipher } = await wa.encryptBytes(state.vaultKey, frontFullBytes);
  const { iv: thumbIv, cipher: thumbCipher } = await wa.encryptBytes(state.vaultKey, frontThumbBytes);
  const { iv: metaIv, cipher: metaCipher } = await wa.encryptJson(state.vaultKey, { title });
  const id = crypto.randomUUID();
  const now = Date.now();
  const record = {
    id, folderId: folderId || null, type: 'document', createdAt: now, updatedAt: now, mimeType,
    metaIv, metaCipher, fileIv, fileCipher, thumbIv, thumbCipher,
  };
  if (verso) {
    const backFullBytes = new Uint8Array(await verso.fullBlob.arrayBuffer());
    const backThumbBytes = new Uint8Array(await verso.thumbBlob.arrayBuffer());
    const { iv: backIv, cipher: backCipher } = await wa.encryptBytes(state.vaultKey, backFullBytes);
    const { iv: backThumbIv, cipher: backThumbCipher } = await wa.encryptBytes(state.vaultKey, backThumbBytes);
    record.backIv = backIv;
    record.backCipher = backCipher;
    record.backThumbIv = backThumbIv;
    record.backThumbCipher = backThumbCipher;
  }
  await db.putItem(record);
  state.items.push({ id, folderId: record.folderId, type: 'document', title, createdAt: now, updatedAt: now, mimeType, _record: record });
  renderFolders();
  renderItems();
}

async function saveNewPassword({ title, username, password, notes, folderId }) {
  const { iv: metaIv, cipher: metaCipher } = await wa.encryptJson(state.vaultKey, { title, username, password, notes });
  const id = crypto.randomUUID();
  const now = Date.now();
  const record = { id, folderId: folderId || null, type: 'password', createdAt: now, updatedAt: now, metaIv, metaCipher };
  await db.putItem(record);
  state.items.push({ id, folderId: record.folderId, type: 'password', title, username, password, notes, createdAt: now, updatedAt: now, _record: record });
  renderFolders();
  renderItems();
}

$('form-add-document').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!pendingDoc.front) return;
  const title = $('doc-title').value.trim() || '(Sans titre)';
  const folderId = $('doc-folder').value || null;
  try {
    await saveNewDocument({ ...pendingDoc, title, folderId });
    $('dialog-add').close();
    showToast('Document ajouté.');
  } catch (err) {
    console.error(err);
    showToast('Erreur lors de l\'enregistrement.');
  }
});

$('form-add-password').addEventListener('submit', async (e) => {
  e.preventDefault();
  const title = $('new-pwd-title').value.trim() || '(Sans titre)';
  const username = $('new-pwd-username').value.trim();
  const password = $('new-pwd-password').value;
  const notes = $('new-pwd-notes').value.trim();
  const folderId = $('new-pwd-folder').value || null;
  try {
    await saveNewPassword({ title, username, password, notes, folderId });
    $('dialog-add').close();
    showToast('Mot de passe ajouté.');
  } catch (err) {
    console.error(err);
    showToast('Erreur lors de l\'enregistrement.');
  }
});

// ---------------------------------------------------------------------------
// Dialogues génériques (confirmation, phrase secrète)
// ---------------------------------------------------------------------------
function confirmDialog(message) {
  const dlg = $('dialog-confirm');
  $('confirm-message').textContent = message;
  dlg.showModal();
  return new Promise((resolve) => {
    let done = false;
    function finish(result) {
      if (done) return;
      done = true;
      $('confirm-ok').removeEventListener('click', onOk);
      $('confirm-cancel').removeEventListener('click', onCancel);
      dlg.removeEventListener('close', onClose);
      resolve(result);
    }
    function onOk() { finish(true); dlg.close(); }
    function onCancel() { dlg.close(); }
    function onClose() { finish(false); }
    $('confirm-ok').addEventListener('click', onOk);
    $('confirm-cancel').addEventListener('click', onCancel);
    dlg.addEventListener('close', onClose);
  });
}

function promptPassphrase(mode) {
  const dlg = $('dialog-passphrase');
  const input1 = $('passphrase-input-1');
  const input2 = $('passphrase-input-2');
  input1.value = '';
  input2.value = '';
  if (mode === 'new') {
    $('passphrase-title').textContent = 'Choisis une phrase secrète';
    $('passphrase-explain').textContent =
      "Cet appareil ne permet pas de dériver directement une clé de chiffrement depuis Face ID / Touch ID. " +
      "Cette phrase secrète protège ton coffre en plus de la biométrie (redemandée à chaque ouverture). " +
      "Note-la précieusement : elle ne peut pas être récupérée si tu l'oublies.";
    $('passphrase-confirm-wrap').hidden = false;
    input2.required = true;
  } else {
    $('passphrase-title').textContent = 'Phrase secrète';
    $('passphrase-explain').textContent = 'Entre ta phrase secrète pour terminer le déverrouillage.';
    $('passphrase-confirm-wrap').hidden = true;
    input2.required = false;
  }
  dlg.showModal();
  input1.focus();
  return new Promise((resolve) => {
    let done = false;
    function finish(result) {
      if (done) return;
      done = true;
      $('form-passphrase').removeEventListener('submit', onSubmit);
      dlg.removeEventListener('close', onClose);
      $('passphrase-close').removeEventListener('click', onCancelClick);
      resolve(result);
    }
    function onSubmit(e) {
      e.preventDefault();
      const v1 = input1.value;
      const v2 = input2.value;
      if (mode === 'new' && v1 !== v2) { showToast('Les deux phrases ne correspondent pas.'); return; }
      if (v1.length < 8) { showToast('Utilise au moins 8 caractères.'); return; }
      finish(v1);
      dlg.close();
    }
    function onCancelClick() { dlg.close(); }
    function onClose() { finish(null); }
    $('form-passphrase').addEventListener('submit', onSubmit);
    dlg.addEventListener('close', onClose);
    $('passphrase-close').addEventListener('click', onCancelClick);
  });
}

// Fermer un dialogue en cliquant en dehors de son contenu.
document.querySelectorAll('dialog.dialog:not(.dialog-fullscreen)').forEach((dlg) => {
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });
});

// ---------------------------------------------------------------------------
// Service worker (coquille applicative hors-ligne ; les données restent
// exclusivement dans IndexedDB, jamais mises en cache réseau).
// ---------------------------------------------------------------------------
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch((err) => console.warn('SW non enregistré', err));
  });
}

boot();
