# Kastela SDK for Node.js

Credential is required when using the SDK, download it on the entities page.

Usage Examples :

```js
const protectionId = "28e61e5f-d575-49db-8dfb-1c5063213a76";

const client = new Client(
  "https://127.0.0.1:8080",
  "./ca.crt",
  "./client.crt",
  "./client.key"
);
const data = client.protectionOpen(protectionId, [1, 2, 3, 4]);
```
