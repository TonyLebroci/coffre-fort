// crypto.js — WebAuthn (Face ID / Touch ID) + AES-GCM helpers.
// Tout s'exécute localement dans le navigateur : rien n'est jamais envoyé sur le réseau.

const PRF_INFO = 'coffre-fort-vault-wrap-v1';

export function randomBytes(len) {
  return crypto.getRandomValues(new Uint8Array(len));
}

export async function isPlatformAuthenticatorAvailable() {
  if (!window.PublicKeyCredential) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

// Crée le passkey lié à Face ID / Touch ID (authenticator "platform").
export async function createPasskey() {
  const challenge = randomBytes(32);
  const userId = randomBytes(16);
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: 'Coffre-fort' },
      user: { id: userId, name: 'coffre-fort', displayName: 'Coffre-fort' },
      challenge,
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },   // ES256
        { alg: -257, type: 'public-key' }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
      extensions: { prf: {} },
      timeout: 60000,
      attestation: 'none',
    },
  });
  return { rawId: cred.rawId, userId };
}

// Demande une confirmation biométrique et récupère le secret PRF (si le
// navigateur/l'authentificateur le supporte). Ce secret est déterministe :
// il est dérivé du credential + du sel fourni, jamais stocké tel quel.
export async function getPrfSecret(rawId, salt) {
  const challenge = randomBytes(32);
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ id: rawId, type: 'public-key' }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const ext = assertion.getClientExtensionResults();
  const secret = ext.prf && ext.prf.results ? ext.prf.results.first : undefined;
  return secret ? new Uint8Array(secret) : null;
}

// Simple porte biométrique (sans PRF) : confirme la présence de l'utilisateur.
export async function assertPresenceOnly(rawId) {
  const challenge = randomBytes(32);
  await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ id: rawId, type: 'public-key' }],
      userVerification: 'required',
    },
  });
}

async function hkdfKey(secretBytes, usages) {
  const base = await crypto.subtle.importKey('raw', secretBytes, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(PRF_INFO) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}

export function deriveWrappingKeyFromPrf(secretBytes) {
  return hkdfKey(secretBytes, ['wrapKey', 'unwrapKey']);
}

export async function deriveKeyFromPassphrase(passphrase, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 310000 },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

export function generateVaultKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function wrapVaultKey(vaultKey, wrappingKey) {
  const iv = randomBytes(12);
  const wrapped = await crypto.subtle.wrapKey('raw', vaultKey, wrappingKey, { name: 'AES-GCM', iv });
  return { wrapped, iv };
}

export function unwrapVaultKey(wrapped, iv, wrappingKey) {
  return crypto.subtle.unwrapKey(
    'raw', wrapped, wrappingKey,
    { name: 'AES-GCM', iv },
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptBytes(vaultKey, bytes) {
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vaultKey, bytes);
  return { iv, cipher };
}

export function decryptBytes(vaultKey, iv, cipher) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, vaultKey, cipher);
}

export async function encryptJson(vaultKey, obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  return encryptBytes(vaultKey, bytes);
}

export async function decryptJson(vaultKey, iv, cipher) {
  const bytes = await decryptBytes(vaultKey, iv, cipher);
  return JSON.parse(new TextDecoder().decode(bytes));
}
