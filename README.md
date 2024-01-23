# client-api

A library for handling encryption and decryption of WebSocket data (and later HTTP) from a Kinode.

## Installation

`npm install @kinode/client-api`
or
`yarn add @kinode/client-api`

## How to use

Import and instantiate the KinodeClientApi:


```
import KinodeClientApi from '@kinode/client-api'
const api = new KinodeClientApi({
  nodeId, // You should set this on the window and then pass in. See the apps_home html for an example.
  channelId, // The channel that WS messages will come over, usually the process name or ID.
  uri = 'ws://' + window.location.host,
  onMessage = () => null, // Handle WS message
  onEncryptionReady = () => null, // Called when end-to-end encryption with the Kinode is ready. Recommended to use this instead of onOpen
  onOpen = () => null, // Handle WS open
  onClose = () => null, // Handle WS close
  onError = () => null, // Handle WS error
})
```
