import forge from 'node-forge'
import { Buffer } from 'buffer'

interface ProcessId {
  process_name: string,
  package_name: string,
  publisher_node: string,
}

const processToString = (process: ProcessId): string => {
  return `${process.process_name}:${process.package_name}:${process.publisher_node}`
}

const processFromString = (process: string): ProcessId => {
  const [process_name, package_name, publisher_node] = process.split(':')
  return { process_name, package_name, publisher_node }
}

function getCookie(name: string) {
  const cookies = document.cookie.split(';')
  for (let i = 0; i < cookies.length; i++) {
    const cookie = cookies[i].trim()
    if (cookie.startsWith(name)) {
      return cookie.substring(name.length + 1)
    }
  }
}

function stringifyAndEncode(data: any) {
  const json = JSON.stringify(data)
  const encoder = new TextEncoder();
  const bytes = encoder.encode(json);
  return bytes
}

function blobToUint8Array(blob: Blob): Promise<Uint8Array> { // eslint-disable-line
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = reject
    reader.onload = function(event: any) {
        const arrayBuffer = event.target.result;
        const uint8Array = new Uint8Array(arrayBuffer);
        resolve(uint8Array)
    };
    reader.readAsArrayBuffer(blob);
  })
}

interface SendParams {
  data: any // eslint-disable-line
  channelId?: string
  encrypted?: boolean
  target?: { node: string, process: ProcessId }
}

export default class UqbarEncryptorApi {
  // 1. Generate a keypair
  nodeId?: string;
  processId: ProcessId;
  channelId: number | undefined;
  _secret: string | undefined;
  _cipher: forge.cipher.BlockCipher | undefined; // eslint-disable-line
  _decipher: forge.cipher.BlockCipher | undefined; // eslint-disable-line
  _ws: WebSocket;

  constructor({
    nodeId,
    processId,
    channelId,
    uri = `${window.location.protocol.replace('http', 'ws')}//${window.location.host}/${processId}/`,
    onMessage = () => null,
    onOpen = () => null,
    onClose = () => null,
    onError = () => null,
    // onEncryptionReady = () => null,
  }: {
    nodeId: string,
    processId: string,
    channelId?: number,
    uri?: string,
    onMessage?: (data: any, api: UqbarEncryptorApi) => void, // eslint-disable-line
    onOpen?: (ev: Event, api: UqbarEncryptorApi) => void,
    onClose?: (ev: CloseEvent) => void,
    onError?: (ev: Event) => void,
    // onEncryptionReady?: (api: UqbarEncryptorApi) => void,
  }) {
    this._secret = undefined;
    this.processId = processFromString(processId);
    this.channelId = channelId;
    this.nodeId = nodeId;
    this._ws = new WebSocket(uri)
    this._ws.onmessage = async (ev: MessageEvent<string | Blob>) => { // eslint-disable-line
      onMessage(ev.data, this)
      // figure out if it's encrypted, if it is, decrypt it and then pass to onMessage
      // if (typeof ev.data === 'string') {
      //   onMessage(ev.data, this)
      // } else if (ev.data instanceof Blob) {
      //   const encrypted = await blobToUint8Array(ev.data)
      //   const decrypted: any = this._decrypt(encrypted) // eslint-disable-line
      //   if (decrypted === null) {
      //     console.log('Unable to decrypt message, passing through as-is')
      //     const string = new TextDecoder().decode(encrypted);
      //     onMessage(string, this)
      //   } else {
      //     onMessage(decrypted, this)
      //   }
      // } else {
      //   onMessage(ev.data, this)
      // }
    }
    this._ws.onopen = (ev: Event) => {
      // Register this API instance with the server
      console.log(`${nodeId}`, getCookie(`kinode-auth_${nodeId}`),getCookie(`kinode-ws-auth_${nodeId}`))
      this._ws.send(stringifyAndEncode({
          auth_token: getCookie(`kinode-auth_${nodeId}`),
          // ws_auth_token: getCookie(`kinode-ws-auth_${nodeId}`),
          // channel_id: channelId,
          target_process: processId,
          encrypted: false,
      }))
      onOpen(ev, this)
    }
    this._ws.onclose = onClose
    this._ws.onerror = onError

    // const rsa = forge.pki.rsa; // eslint-disable-line
    // const keypair = rsa.generateKeyPair({bits: 2048, e: 65537}); // eslint-disable-line

    // const publicKeyHex = keypair.publicKey.n.toString(16) // eslint-disable-line

    // fetch(genFetchRoute('/encryptor:sys:kinode'), {
    //   method: 'POST',
    //   body: JSON.stringify({
    //     channel_id: channelId,
    //     public_key_hex: publicKeyHex,
    //   })
    // }).then(r => r.json()).then((json: { encrypted_secret: string, signed_public_key: string }) => {
    //   const { encrypted_secret, signed_public_key } = json
    //   fetch(`/qns_indexer:qns_indexer:kinode/node/${this.nodeId}`).then(r => r.json()).then((pqi: any) => { // eslint-disable-line
    //     const { public_key } = pqi
    //     console.log(this.nodeId)
    //     console.log('Got public key from QNS:', public_key)
    //     // get the public key from the json
    //     const networkingPublicKey = public_key.replace('0x', '')

    //     if (!networkingPublicKey) return

    //     const verified: boolean = forge.pki.ed25519.verify({
    //       message: Buffer.from(publicKeyHex, 'hex'),
    //       signature: Buffer.from(signed_public_key, 'hex'),
    //       publicKey: Buffer.from(networkingPublicKey, 'hex'),
    //     })

    //     console.log('Verified:', verified)

    //     if (true || verified) {
    //       const encryptedBytes = forge.util.hexToBytes(encrypted_secret)
    //       // dc72a3afeb53d5c84c1143d179b041ccf121aff3854ec14c27080ea3eba801d1 - the secret key we expect to see
    //       const secretKey = keypair.privateKey.decrypt(encryptedBytes, "RSA-OAEP", {
    //         md: forge.md.sha256.create()
    //       }) // eslint-disable-line

    //       this._secret = forge.util.bytesToHex(secretKey)
    //       this._cipher = forge.cipher.createCipher('AES-GCM', secretKey);
    //       this._decipher = forge.cipher.createDecipher('AES-GCM', secretKey);
    //       onEncryptionReady(this)
    //     } else {
    //       console.error('Unable to verify networking key')
    //     }

    //   }).catch(console.error)
    // }).catch(console.error)
  }

  // methods
  _encrypt = (message: string) => {
  //   if (this._cipher) {
  //     const nonce = forge.random.getBytesSync(12);

  //     this._cipher.start({ iv: nonce });
  //     this._cipher.update(forge.util.createBuffer(message, 'utf8'));
  //     this._cipher.finish();

  //     const encryptedData = this._cipher.output.getBytes();
  //     const tag = this._cipher.mode.tag.getBytes();

  //     return { encrypted: encryptedData + tag, nonce }
  //   }

    return null
  }
  _decrypt = (dataAndNonce: Uint8Array): any => { // eslint-disable-line
  //   if (!this._decipher) return null

  //   const encryptedBytes = dataAndNonce.slice(0, -28)
  //   const tagBytes = dataAndNonce.slice(-28, -12)
  //   const nonceBytes = dataAndNonce.slice(-12)

  //   this._decipher.start({
  //     iv: forge.util.createBuffer(nonceBytes),
  //     tag: forge.util.createBuffer(tagBytes),
  //   })
  //   this._decipher.update(forge.util.createBuffer(encryptedBytes))
  //   const pass = this._decipher.finish()

  //   if (!pass) return null

  //   return this._decipher.output.toString() as string // eslint-disable-line
  }
  send = ({ data }: SendParams) => {
    const auth_token = getCookie(`kinode-auth_${this.nodeId}`) // eslint-disable-line
    const ws_auth_token = getCookie(`kinode-ws-auth_${this.nodeId}`) // eslint-disable-line

    // if (encrypted) {
    //   if (!this._cipher) return console.error('No cipher, unable to encrypt')
    //   this._ws.send(stringifyAndEncode({
    //     EncryptedWsMessage: {
    //       auth_token,
    //       ws_auth_token,
    //       channel_id: channelId,
    //       target,
    //       ...this._encrypt(JSON.stringify(data))
    //     }
    //   }))
    // } else {
      this._ws.send(stringifyAndEncode(
        data
      // {
      //   channel_id: this.channelId,
      //   operation: data
      // }
        // WsMessage: {
        //   auth_token,
        //   ws_auth_token,
        //   channel_id: channelId,
        //   target: {
        //     node: target.node,
        //     process: typeof target.process === 'number' ? { Id: target.process } : { Name: target.process }
        //   },
        //   json: data, // eslint-disable-line
        // }
      ))
    // }
  }
  fetchJson = async <T>(input: RequestInfo | URL, init?: RequestInit | undefined): Promise<T> => {
    console.log('Fetching JSON:', input)
    const response = await fetch(input, init)
    const json: T = await (response.json() as Promise<T>)
    return json
  }
}
