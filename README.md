# client-encryptor-api

A library for handling encryption and decryption of WebSocket data (and later HTTP) from an Uqbar node.

## How to use

Import and instantiate the UqbarEncryptorApi:

```
import UqbarEncryptorApi from '@uqbar/client-encryptor'
const api = new UqbarEncryptorApi({
  nodeId, // You should set this on the window and then pass in. See the apps_home html for an example.
  channelId, // The channel that WS messages will come over, usually the process name or ID.
  uri = 'ws://' + window.location.host,
  onMessage = () => null, // Handle WS message
  onEncryptionReady = () => null, // Called when end-to-end encryption with the Uqbar node is ready. Recommended to use this instead of onOpen
  onOpen = () => null, // Handle WS open
  onClose = () => null, // Handle WS close
  onError = () => null, // Handle WS error
})
```
