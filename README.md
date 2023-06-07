# Kastela Server SDK for Node.js

## Installation

```bash
npm install @kastela-sdp/kastela-sdk-node
```

## Usage

```js
const { Client } = require("@kastela-sdp/kastela-sdk-node");

const client = new Client(
  "https://127.0.0.1:3100",
  "./ca.crt",
  "./client.crt",
  "./client.key"
);

const protectionID = "28e61e5f-d575-49db-8dfb-1c5063213a76";
const tokens = ["foo", "bar", "baz"];

const data = await client.protectionOpen([{ protectionID, tokens }]);

console.log(data);
```
