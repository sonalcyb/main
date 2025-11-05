import express from 'express';
import cors from 'cors';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import path from 'path';
import url from 'url';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// ====== CONFIG ======
const PORT = process.env.PORT || 8080;
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
const KEY_ID = process.env.RAZORPAY_KEY_ID;
const KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const DOWNLOAD_SECRET = process.env.DOWNLOAD_SECRET || 'change_me';

if (!KEY_ID || !KEY_SECRET) {
  console.error('Missing Razorpay keys. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in .env');
  process.exit(1);
}

const razorpay = new Razorpay({ key_id: KEY_ID, key_secret: KEY_SECRET });

// Map SKU → amount (INR, in paise) and protected download URL
const CATALOG = {
  'eb-js-beg': { title: 'JavaScript for Beginners (e‑Book)', amount: 100, url: 'https://drive.google.com/uc?export=download&id=YOUR_SAMPLE_ID1' },
  'eb-python-pro': { title: 'Python Pro Handbook (e‑Book)', amount: 24900, url: 'https://drive.google.com/uc?export=download&id=YOUR_SAMPLE_ID2' },
  'pdf-dsa-kit': { title: 'DSA Crash Kit (PDF Notes)', amount: 17900, url: 'https://drive.google.com/uc?export=download&id=YOUR_SAMPLE_ID3' },
  'sw-win-tool': { title: 'Win Optimizer Tool', amount: 29900, url: 'https://example.com/your-app.zip' },
  'crs-web-bundle': { title: 'Full Web Dev Bundle', amount: 49900, url: 'https://drive.google.com/uc?export=download&id=YOUR_SAMPLE_ID4' }
};

// ====== API: Create Order ======
app.post('/api/order', async (req, res) => {
  try {
    const { sku } = req.body;
    const item = CATALOG[sku];
    if (!item) return res.status(400).json({ ok: false, error: 'Invalid SKU' });

    const receipt = `rcpt_${sku}_${Date.now()}`;
    const order = await razorpay.orders.create({
      amount: item.amount, // in paise
      currency: 'INR',
      receipt,
      notes: { sku }
    });

    return res.json({ ok: true, orderId: order.id, keyId: KEY_ID, amount: item.amount, currency: 'INR', sku });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Order creation failed' });
  }
});

// ====== API: Verify Payment ======
app.post('/api/verify', (req, res) => {
  try {
    const { sku, razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    if (!sku) return res.status(400).json({ ok: false, error: 'Missing sku' });
    const item = CATALOG[sku];
    if (!item) return res.status(400).json({ ok: false, error: 'Invalid SKU' });

    const hmac = crypto.createHmac('sha256', KEY_SECRET);
    hmac.update(`${razorpay_order_id}|${razorpay_payment_id}`);
    const expected = hmac.digest('hex');

    if (expected !== razorpay_signature) {
      return res.status(400).json({ ok: false, error: 'Signature mismatch' });
    }

    // Create signed download token valid for 1 hour
    const token = jwt.sign({ sku }, DOWNLOAD_SECRET, { expiresIn: '1h' });
    const downloadUrl = `${PUBLIC_URL}/download?token=${token}`;
    return res.json({ ok: true, downloadUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Verification failed' });
  }
});

// ====== Protected download redirect ======
app.get('/download', (req, res) => {
  const { token } = req.query;
  try {
    const data = jwt.verify(token, DOWNLOAD_SECRET);
    const item = CATALOG[data.sku];
    if (!item) return res.status(404).send('Not found');
    // Redirect to the real file URL. The token expires in 1 hour.
    return res.redirect(item.url);
  } catch (err) {
    return res.status(401).send('Link expired or invalid');
  }
});

// ====== Static hosting for frontend ======
const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`DigiCart server running on ${PUBLIC_URL}`);
});
