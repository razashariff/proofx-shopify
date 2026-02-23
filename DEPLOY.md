# ProofX Shopify App — Deployment Guide

## Prerequisites

- Node.js 18+
- Shopify Partners account (partners.shopify.com)
- fly.io account with `flyctl` installed
- ProofX account (proofx.co.uk)

## 1. Create Shopify App

1. Go to **partners.shopify.com** > Apps > Create app > Custom app
2. Set **App URL**: `https://proofx-shopify.fly.dev/`
3. Set **Allowed redirection URL(s)**: `https://proofx-shopify.fly.dev/auth/callback`
4. Under **App setup**, request these scopes: `read_products, write_products`
5. Copy the **API key** and **API secret key**

## 2. Configure Webhooks in Shopify Partners

In the app settings under **Event subscriptions**:

| Event | Endpoint |
|-------|----------|
| `products/create` | `https://proofx-shopify.fly.dev/webhooks/products-create` |
| `products/update` | `https://proofx-shopify.fly.dev/webhooks/products-update` |
| `app/uninstalled` | `https://proofx-shopify.fly.dev/webhooks/app-uninstalled` |

Webhook format: **JSON**

Note: The app also registers these webhooks programmatically during OAuth install,
so manual registration is optional but recommended as a fallback.

## 3. Deploy to fly.io

```bash
cd /Users/razasharif/Downloads/proofx-shopify

# Create the app (first time only)
fly launch --name proofx-shopify --region lhr --no-deploy

# Set secrets
fly secrets set \
  SHOPIFY_API_KEY="your_shopify_api_key" \
  SHOPIFY_API_SECRET="your_shopify_api_secret" \
  SHOPIFY_SCOPES="read_products,write_products" \
  HOST="https://proofx-shopify.fly.dev" \
  PROOFX_CREATOR_ID="your_creator_id" \
  PROOFX_API_KEY="your_api_key"

# Deploy
fly deploy --app proofx-shopify
```

## 4. Persistent Storage (Optional)

The app stores shop data in `shops.json`. On fly.io, this file is ephemeral
(lost on redeploy). For production persistence:

```bash
# Create a volume
fly volumes create proofx_data --size 1 --region lhr --app proofx-shopify
```

Add to `fly.toml`:

```toml
[mounts]
  source = "proofx_data"
  destination = "/data"
```

Then set in secrets:

```bash
fly secrets set SHOPS_FILE="/data/shops.json" --app proofx-shopify
```

And update `server.js` line:

```js
const SHOPS_FILE = process.env.SHOPS_FILE || path.join(__dirname, "shops.json");
```

## 5. Install on a Shopify Store

Visit:

```
https://proofx-shopify.fly.dev/auth?shop=YOUR-STORE.myshopify.com
```

Or go to `https://proofx-shopify.fly.dev/` and enter your store URL.

## 6. Configure ProofX Settings

After installing, the embedded app opens in Shopify admin. Go to the
**Settings** tab and enter:

- **Creator ID**: Your ProofX creator ID (from proofx.co.uk dashboard)
- **API Key**: Your ProofX API key (from proofx.co.uk/developer)

## Local Development

```bash
# Copy env
cp .env.example .env
# Fill in values

# Install dependencies
npm install

# Run (with auto-reload)
npm run dev

# Use ngrok for Shopify webhooks
ngrok http 3000
# Update HOST in .env and Shopify Partners redirect URLs
```

## Architecture

```
Shopify Store
    |
    |-- product create/update webhook -->  proofx-shopify (fly.io)
    |                                          |
    |                                          |-- download image
    |                                          |-- SHA-256 hash
    |                                          |-- POST sign-hash --> api.proofx.co.uk
    |                                          |-- store content_id
    |
    |-- admin panel (App Bridge) ----------->  embedded UI
```

## Troubleshooting

- **OAuth fails**: Check SHOPIFY_API_KEY and SHOPIFY_API_SECRET are correct
- **Webhooks not firing**: Verify webhook URLs in Shopify Partners dashboard
- **Images not protecting**: Check Creator ID is set in Settings tab
- **Health check**: GET `https://proofx-shopify.fly.dev/health`
