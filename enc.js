(() => {
  const ALGO = { name: 'AES-CBC', length: 128 };
  const enc = new TextEncoder('utf-8');

  const randBytes = () => crypto.getRandomValues(new Uint8Array(16));

  /** generate and export an AES key */
  const genKey = async () =>
    crypto.subtle.exportKey(
      'raw',
      await crypto.subtle.generateKey(ALGO, true, ['encrypt', 'decrypt'])
    );

  /** import AES key */
  const importKey = key =>
    crypto.subtle.importKey('jwk', key, ALGO, true, ['encrypt', 'decrypt']);

  /** decrypt some ciphertext */
  const decrypt = async (aesKey, iv, ciphertext) =>
    [
      ...new Uint8Array(
        await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ciphertext)
      ),
    ]
      .map(c => String.fromCharCode(c))
      .join('');

  /** encrypt some text */
  const encrypt = async (aesKey, plaintext) => {
    const iv = randBytes();
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      aesKey,
      enc.encode(plaintext)
    );
    return [iv, new Uint8Array(ciphertext)];
  };

  /** decode a hex string into an array */
  const hexDecode = str => {
    if (str.length % 2) throw 'String must be even length';
    const buf = new Uint8Array(str.length / 2);
    for (let i = 0; i < str.length; i += 2) {
      buf[i / 2] = parseInt(str[i] + str[i + 1], 16);
    }
    return buf;
  };

  /** encode an array into a hex string */
  const hexEncode = buf =>
    [...buf].map(b => b.toString(16).padStart(2, '0')).join('');

  /** encrypt some text and encode it */
  const encryptEncode = async (aesKey, plaintext) =>
    (await encrypt(aesKey, plaintext)).map(hexEncode).join(';');

  const decryptDecode = (aesKey, encoded) =>
    decrypt(aesKey, ...encoded.split(';').map(hexDecode));

  // symmetric encryption key
  const KEY = {
    alg: 'A128CBC',
    ext: true,
    k: '2w8eyMzkuju4Suv6K6yo3g',
    key_ops: ['encrypt', 'decrypt'],
    kty: 'oct',
  };

  // decrypt some data on dom load
  document.addEventListener('DOMContentLoaded', async () => {
    const aesKey = await importKey(KEY);
    document.title = await decryptDecode(
      aesKey,
      'f1f6cc94b63ecc7782ac2742c70b7515;a4ba46732f7883a9592174965eb9d136ccff28f91fd2f0a4155fdc5753424d8d'
    );

    for (const elem of Array.from(
      document.body.querySelectorAll('[enc-html]')
    )) {
      await new Promise(resolve => setTimeout(resolve, 50));
      decryptDecode(aesKey, elem.getAttribute('enc-html')).then(text => {
        elem.innerHTML = text;
        elem.removeAttribute('enc-html');
      });
    }
    for (const elem of Array.from(
      document.body.querySelectorAll('[enc-href]')
    )) {
      decryptDecode(aesKey, elem.getAttribute('enc-href')).then(text => {
        elem.setAttribute('href', text);
        elem.removeAttribute('enc-href');
      });
    }

    // helper for encoding new text
    const toEncode = [];
    for (const str of toEncode) {
      console.log(str, await encryptEncode(aesKey, str));
    }
  });
})();
