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

const data = await client.protectionOpen([{
  protectionID: "your-protection-id",
  tokens: ["foo", "bar", "baz"]
}]);

console.log(data);
```

## Reference

- [Documentation](https://kastela-sdp.github.io/kastela-sdk-node)
