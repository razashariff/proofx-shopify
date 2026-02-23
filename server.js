/**
 * ProofX Shopify App — server.js
 *
 * Express server handling:
 *   - Shopify OAuth (install + callback)
 *   - Webhook verification and processing (products/create, products/update)
 *   - ProofX sign-hash integration (auto-protect product images)
 *   - Embedded admin UI served via Shopify App Bridge
 *   - Per-shop settings stored in shops.json
 */

require("dotenv").config();

const express = require("express");
const crypto = require("crypto");
const fetch = require("node-fetch");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SHOPIFY_SCOPES = "read_products,write_products",
  HOST,
  PROOFX_CREATOR_ID,
  PROOFX_API_KEY,
} = process.env;

const PROOFX_API_BASE = "https://api.proofx.co.uk";
const SHOPS_FILE = process.env.SHOPS_FILE || path.join(__dirname, "shops.json");
const PORT = process.env.PORT || 3000;

if (!SHOPIFY_API_KEY || !SHOPIFY_API_SECRET || !HOST) {
  console.error(
    "Missing required env vars: SHOPIFY_API_KEY, SHOPIFY_API_SECRET, HOST"
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Shop store (JSON file)
// ---------------------------------------------------------------------------

/**
 * Shop data shape:
 * {
 *   "shop-name.myshopify.com": {
 *     "accessToken": "...",
 *     "creatorId": "...",
 *     "apiKey": "...",
 *     "protectedImages": [
 *       { "contentId": "...", "productId": 123, "productTitle": "...",
 *         "imageId": 456, "imageSrc": "...", "hash": "...", "protectedAt": "..." }
 *     ],
 *     "installedAt": "..."
 *   }
 * }
 */

function loadShops() {
  try {
    if (fs.existsSync(SHOPS_FILE)) {
      return JSON.parse(fs.readFileSync(SHOPS_FILE, "utf-8"));
    }
  } catch (err) {
    console.error("Failed to load shops.json, starting fresh:", err.message);
  }
  return {};
}

function saveShops(shops) {
  fs.writeFileSync(SHOPS_FILE, JSON.stringify(shops, null, 2), "utf-8");
}

let shops = loadShops();

function getShop(shop) {
  return shops[shop] || null;
}

function setShop(shop, data) {
  shops[shop] = { ...(shops[shop] || {}), ...data };
  saveShops(shops);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildNonce() {
  return uuidv4().replace(/-/g, "");
}

function verifyHmac(queryParams) {
  const { hmac, ...rest } = queryParams;
  if (!hmac) return false;

  const keys = Object.keys(rest).sort();
  const message = keys.map((k) => `${k}=${rest[k]}`).join("&");
  const digest = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(message)
    .digest("hex");

  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
}

function verifyWebhookHmac(body, hmacHeader) {
  const digest = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(body, "utf-8")
    .digest("base64");

  return crypto.timingSafeEqual(
    Buffer.from(digest),
    Buffer.from(hmacHeader)
  );
}

async function sha256Hex(buffer) {
  const hash = crypto.createHash("sha256").update(buffer).digest("hex");
  return hash;
}

// ---------------------------------------------------------------------------
// ProofX API calls
// ---------------------------------------------------------------------------

async function proofxSignHash({ contentHash, creatorId, apiKey, title }) {
  const headers = { "Content-Type": "application/json" };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }

  const res = await fetch(`${PROOFX_API_BASE}/api/content/sign-hash`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      content_hash: contentHash,
      creator_id: creatorId,
      title: title || "Shopify Product Image",
      content_type: "image",
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`ProofX sign-hash failed (${res.status}): ${text}`);
  }

  const data = await res.json();

  if (!data.success) {
    throw new Error(
      data.message || data.error || "ProofX sign-hash returned success=false"
    );
  }

  return data;
}

async function proofxVerify(contentId) {
  const res = await fetch(`${PROOFX_API_BASE}/api/content/${contentId}`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`ProofX verify failed (${res.status}): ${text}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Image processing
// ---------------------------------------------------------------------------

async function downloadImage(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Image download failed: ${res.status}`);
  return res.buffer();
}

async function protectProductImages(shop, product) {
  const shopData = getShop(shop);
  if (!shopData || !shopData.creatorId) {
    console.log(`[${shop}] No creator_id configured, skipping protection`);
    return;
  }

  const { creatorId, apiKey, protectedImages = [] } = shopData;
  const images = product.images || [];

  if (images.length === 0) {
    console.log(
      `[${shop}] Product ${product.id} "${product.title}" has no images`
    );
    return;
  }

  console.log(
    `[${shop}] Protecting ${images.length} image(s) for product ${product.id} "${product.title}"`
  );

  const newProtected = [];

  for (const image of images) {
    // Skip already-protected images
    const alreadyProtected = protectedImages.find(
      (p) => p.imageId === image.id && p.productId === product.id
    );
    if (alreadyProtected) {
      console.log(
        `  Image ${image.id} already protected as ${alreadyProtected.contentId}`
      );
      continue;
    }

    try {
      const buffer = await downloadImage(image.src);
      const hash = await sha256Hex(buffer);
      const title = `${product.title} - ${path.basename(
        new URL(image.src).pathname
      )}`;

      const result = await proofxSignHash({
        contentHash: hash,
        creatorId,
        apiKey,
        title,
      });

      const entry = {
        contentId: result.content_id,
        productId: product.id,
        productTitle: product.title,
        imageId: image.id,
        imageSrc: image.src,
        hash,
        signature: result.signature,
        protectedAt: new Date().toISOString(),
      };

      newProtected.push(entry);
      console.log(
        `  Protected image ${image.id} -> content_id: ${result.content_id}`
      );
    } catch (err) {
      console.error(`  Failed to protect image ${image.id}:`, err.message);
    }
  }

  if (newProtected.length > 0) {
    setShop(shop, {
      protectedImages: [...protectedImages, ...newProtected],
    });
  }
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();

// Raw body for webhook HMAC verification
app.use(
  "/webhooks",
  express.raw({ type: "application/json" }),
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use("/public", express.static(path.join(__dirname, "public")));

// ---------------------------------------------------------------------------
// Shopify OAuth
// ---------------------------------------------------------------------------

// Step 1: Redirect merchant to Shopify OAuth consent screen
app.get("/auth", (req, res) => {
  const { shop } = req.query;
  if (!shop || !shop.match(/^[a-zA-Z0-9][a-zA-Z0-9-]*\.myshopify\.com$/)) {
    return res.status(400).send("Missing or invalid shop parameter");
  }

  const nonce = buildNonce();
  res.cookie("shopify_nonce", nonce, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 600000,
  });

  const redirectUri = `${HOST}/auth/callback`;
  const authUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${SHOPIFY_SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${nonce}`;

  res.redirect(authUrl);
});

// Step 2: OAuth callback — exchange code for access token
app.get("/auth/callback", async (req, res) => {
  const { shop, code, state, hmac } = req.query;

  // Verify HMAC
  if (!verifyHmac(req.query)) {
    return res.status(403).send("HMAC verification failed");
  }

  // Verify nonce
  const savedNonce = req.cookies.shopify_nonce;
  if (!savedNonce || savedNonce !== state) {
    return res.status(403).send("Nonce mismatch — possible CSRF");
  }
  res.clearCookie("shopify_nonce");

  // Exchange code for access token
  try {
    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
      }),
    });

    if (!tokenRes.ok) {
      const text = await tokenRes.text();
      throw new Error(`Token exchange failed: ${text}`);
    }

    const { access_token } = await tokenRes.json();

    // Save shop
    setShop(shop, {
      accessToken: access_token,
      creatorId: PROOFX_CREATOR_ID || "",
      apiKey: PROOFX_API_KEY || "",
      protectedImages: getShop(shop)?.protectedImages || [],
      installedAt: getShop(shop)?.installedAt || new Date().toISOString(),
    });

    // Register webhooks
    await registerWebhooks(shop, access_token);

    // Redirect to embedded app
    res.redirect(`https://${shop}/admin/apps/${SHOPIFY_API_KEY}`);
  } catch (err) {
    console.error("OAuth callback error:", err.message);
    res.status(500).send("Authentication failed. Please try again.");
  }
});

// ---------------------------------------------------------------------------
// Webhook registration
// ---------------------------------------------------------------------------

async function registerWebhooks(shop, accessToken) {
  const webhooks = [
    { topic: "products/create", address: `${HOST}/webhooks/products-create` },
    { topic: "products/update", address: `${HOST}/webhooks/products-update` },
    { topic: "app/uninstalled", address: `${HOST}/webhooks/app-uninstalled` },
  ];

  for (const wh of webhooks) {
    try {
      const res = await fetch(
        `https://${shop}/admin/api/2024-01/webhooks.json`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": accessToken,
          },
          body: JSON.stringify({
            webhook: {
              topic: wh.topic,
              address: wh.address,
              format: "json",
            },
          }),
        }
      );

      if (res.ok) {
        console.log(`[${shop}] Registered webhook: ${wh.topic}`);
      } else {
        const text = await res.text();
        // 422 usually means already registered — that's fine
        if (res.status !== 422) {
          console.error(
            `[${shop}] Webhook registration failed for ${wh.topic}: ${text}`
          );
        }
      }
    } catch (err) {
      console.error(
        `[${shop}] Webhook registration error for ${wh.topic}:`,
        err.message
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Webhook endpoints
// ---------------------------------------------------------------------------

app.post("/webhooks/products-create", async (req, res) => {
  const hmacHeader = req.headers["x-shopify-hmac-sha256"];
  const shopHeader = req.headers["x-shopify-shop-domain"];

  if (!hmacHeader || !verifyWebhookHmac(req.body, hmacHeader)) {
    console.warn("Webhook HMAC verification failed");
    return res.status(401).send("Unauthorized");
  }

  res.status(200).send("OK");

  // Process asynchronously
  try {
    const product = JSON.parse(req.body.toString());
    console.log(
      `[${shopHeader}] Webhook: products/create — ${product.id} "${product.title}"`
    );
    await protectProductImages(shopHeader, product);
  } catch (err) {
    console.error("Webhook products/create error:", err.message);
  }
});

app.post("/webhooks/products-update", async (req, res) => {
  const hmacHeader = req.headers["x-shopify-hmac-sha256"];
  const shopHeader = req.headers["x-shopify-shop-domain"];

  if (!hmacHeader || !verifyWebhookHmac(req.body, hmacHeader)) {
    console.warn("Webhook HMAC verification failed");
    return res.status(401).send("Unauthorized");
  }

  res.status(200).send("OK");

  try {
    const product = JSON.parse(req.body.toString());
    console.log(
      `[${shopHeader}] Webhook: products/update — ${product.id} "${product.title}"`
    );
    await protectProductImages(shopHeader, product);
  } catch (err) {
    console.error("Webhook products/update error:", err.message);
  }
});

app.post("/webhooks/app-uninstalled", (req, res) => {
  const hmacHeader = req.headers["x-shopify-hmac-sha256"];
  const shopHeader = req.headers["x-shopify-shop-domain"];

  if (!hmacHeader || !verifyWebhookHmac(req.body, hmacHeader)) {
    return res.status(401).send("Unauthorized");
  }

  console.log(`[${shopHeader}] App uninstalled`);

  // Remove shop data
  if (shops[shopHeader]) {
    delete shops[shopHeader];
    saveShops(shops);
  }

  res.status(200).send("OK");
});

// ---------------------------------------------------------------------------
// API endpoints (for the embedded admin UI)
// ---------------------------------------------------------------------------

// Middleware: verify request comes from a valid Shopify session
function verifyShopSession(req, res, next) {
  const shop = req.query.shop || req.body?.shop;
  if (!shop) {
    return res.status(400).json({ error: "Missing shop parameter" });
  }

  const shopData = getShop(shop);
  if (!shopData || !shopData.accessToken) {
    return res.status(401).json({ error: "Shop not authenticated" });
  }

  req.shopDomain = shop;
  req.shopData = shopData;
  next();
}

// Get shop settings and protected images
app.get("/api/shop", verifyShopSession, (req, res) => {
  const { accessToken, ...safe } = req.shopData;
  res.json({
    shop: req.shopDomain,
    creatorId: safe.creatorId || "",
    apiKey: safe.apiKey ? "****" + safe.apiKey.slice(-8) : "",
    hasApiKey: !!safe.apiKey,
    protectedImages: safe.protectedImages || [],
    installedAt: safe.installedAt || null,
  });
});

// Update settings
app.post("/api/settings", verifyShopSession, (req, res) => {
  const { creatorId, apiKey } = req.body;

  const updates = {};
  if (typeof creatorId === "string") updates.creatorId = creatorId.trim();
  if (typeof apiKey === "string") updates.apiKey = apiKey.trim();

  setShop(req.shopDomain, updates);

  res.json({ success: true, message: "Settings saved" });
});

// Verify a content ID
app.get("/api/verify/:contentId", async (req, res) => {
  try {
    const data = await proofxVerify(req.params.contentId);
    res.json(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Manually trigger protection for all products
app.post("/api/protect-all", verifyShopSession, async (req, res) => {
  const { accessToken, creatorId } = req.shopData;

  if (!creatorId) {
    return res
      .status(400)
      .json({ error: "Set your ProofX Creator ID in settings first" });
  }

  try {
    // Fetch all products
    let allProducts = [];
    let pageInfo = null;
    let url = `https://${req.shopDomain}/admin/api/2024-01/products.json?limit=50`;

    while (url) {
      const prodRes = await fetch(url, {
        headers: { "X-Shopify-Access-Token": accessToken },
      });

      if (!prodRes.ok) throw new Error(`Shopify API error: ${prodRes.status}`);

      const data = await prodRes.json();
      allProducts = allProducts.concat(data.products || []);

      // Pagination via Link header
      const link = prodRes.headers.get("link");
      url = null;
      if (link) {
        const nextMatch = link.match(/<([^>]+)>;\s*rel="next"/);
        if (nextMatch) url = nextMatch[1];
      }
    }

    console.log(
      `[${req.shopDomain}] Manual protect-all: ${allProducts.length} products`
    );

    let protectedCount = 0;
    for (const product of allProducts) {
      const before = (getShop(req.shopDomain)?.protectedImages || []).length;
      await protectProductImages(req.shopDomain, product);
      const after = (getShop(req.shopDomain)?.protectedImages || []).length;
      protectedCount += after - before;
    }

    res.json({
      success: true,
      message: `Scanned ${allProducts.length} products, protected ${protectedCount} new images`,
      totalProducts: allProducts.length,
      newlyProtected: protectedCount,
    });
  } catch (err) {
    console.error("Protect-all error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Remove a protected image entry
app.delete(
  "/api/protected/:contentId",
  verifyShopSession,
  (req, res) => {
    const { protectedImages = [] } = req.shopData;
    const filtered = protectedImages.filter(
      (p) => p.contentId !== req.params.contentId
    );

    setShop(req.shopDomain, { protectedImages: filtered });
    res.json({ success: true });
  }
);

// ---------------------------------------------------------------------------
// Embedded app page
// ---------------------------------------------------------------------------

app.get("/", (req, res) => {
  const { shop, hmac, host } = req.query;

  // If no shop param, show a simple install prompt
  if (!shop) {
    return res.send(`
      <!DOCTYPE html>
      <html><head><title>ProofX for Shopify</title></head>
      <body style="font-family:sans-serif;padding:40px;text-align:center">
        <h1>ProofX for Shopify</h1>
        <p>Enter your Shopify store URL to install:</p>
        <form action="/auth" method="GET" style="margin-top:20px">
          <input name="shop" placeholder="your-store.myshopify.com"
            style="padding:10px;width:300px;font-size:16px;border:1px solid #ccc;border-radius:6px" />
          <button type="submit"
            style="padding:10px 24px;font-size:16px;background:#008060;color:#fff;border:none;border-radius:6px;margin-left:8px;cursor:pointer">
            Install
          </button>
        </form>
      </body></html>
    `);
  }

  // Check if shop is authenticated
  const shopData = getShop(shop);
  if (!shopData || !shopData.accessToken) {
    return res.redirect(`/auth?shop=${shop}`);
  }

  // Serve embedded app HTML
  const html = fs.readFileSync(
    path.join(__dirname, "views", "index.html"),
    "utf-8"
  );

  // Inject config into HTML
  const injected = html
    .replace("__SHOPIFY_API_KEY__", SHOPIFY_API_KEY)
    .replace("__SHOP_DOMAIN__", shop)
    .replace("__HOST__", host || "");

  res.send(injected);
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    app: "proofx-shopify",
    shops: Object.keys(shops).length,
    uptime: process.uptime(),
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`ProofX Shopify app running on port ${PORT}`);
  console.log(`Host: ${HOST}`);
  console.log(`Shops loaded: ${Object.keys(shops).length}`);
});
