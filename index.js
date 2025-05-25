const express = require('express');
const crypto = require('crypto');
const https = require('https');
const { URL } = require('url');

const app = express();
const port = 3000;

// Middleware to parse raw body for signature verification
app.use('/webhook', express.raw({ type: 'application/json' }));

app.post('/webhook', async (req, res) => {
  try {
    const headers = req.headers;
    const rawBody = req.body;
    const certUrl = headers['paypal-cert-url'];
    const transmissionId = headers['paypal-transmission-id'];
    const transmissionTime = headers['paypal-transmission-time'];
    const transmissionSig = headers['paypal-transmission-sig'];
    const authAlgo = headers['paypal-auth-algo'];

    // Step 1: Download PayPal's certificate
    const certPem = await downloadCertificate(certUrl);

    // Step 2: Reconstruct the expected signed string
    const expectedSig = `${transmissionId}|${transmissionTime}|${rawBody.toString()}`;

    // Step 3: Verify signature
    const isValid = verifySignature(authAlgo, expectedSig, transmissionSig, certPem);

    if (!isValid) {
      console.error('❌ Invalid webhook signature');
      return res.status(400).send('Invalid signature');
    }

    console.log('✅ Verified webhook');
    const jsonBody = JSON.parse(rawBody.toString());
    console.dir(jsonBody, { depth: null });
    res.status(200).send('Webhook received and verified');
  } catch (err) {
    console.error('❌ Error verifying webhook:', err);
    res.status(500).send('Internal Server Error');
  }
});

function downloadCertificate(certUrl) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(certUrl);
    https.get(urlObj, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

function verifySignature(algorithm, expectedString, transmissionSig, certPem) {
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(expectedString, 'utf8');
  return verifier.verify(certPem, transmissionSig, 'base64');
}

// Handle unknown routes
app.use((req, res) => {
  res.status(404).send(`Cannot ${req.method} ${req.originalUrl}`);
});

app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});
