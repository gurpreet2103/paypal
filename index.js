const express = require('express');
const crypto = require('crypto');
const https = require('https');
const { URL } = require('url');

const app = express();
const port = 3000;

// Only parse raw body for /webhook
app.post('/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const headers = req.headers;
    const rawBody = req.body; // Buffer
    const bodyString = rawBody.toString(); // Must be exact string sent by PayPal

    const transmissionId = headers['paypal-transmission-id'];
    const transmissionTime = headers['paypal-transmission-time'];
    const certUrl = headers['paypal-cert-url'];
    const transmissionSig = headers['paypal-transmission-sig'];
    const authAlgo = headers['paypal-auth-algo'];

    if (!transmissionId || !transmissionTime || !certUrl || !transmissionSig || !authAlgo) {
      return res.status(400).send('Missing PayPal headers');
    }

    // Reconstruct expected signed string
    const expectedString = `${transmissionId}|${transmissionTime}|${bodyString}`;

    // Download the certificate
    const certPem = await downloadCertificate(certUrl);

    // Verify the signature
    const isValid = verifySignature(authAlgo, expectedString, transmissionSig, certPem);

    if (!isValid) {
      console.error('❌ Invalid signature');
      return res.status(400).send('Invalid signature');
    }

    console.log('✅ Verified webhook');
    const parsed = JSON.parse(bodyString);
    console.dir(parsed, { depth: null });
    res.status(200).send('Verified');
  } catch (err) {
    console.error('❌ Webhook error:', err);
    res.status(500).send('Internal error');
  }
});

// Download certificate
function downloadCertificate(certUrl) {
  return new Promise((resolve, reject) => {
    https.get(new URL(certUrl), res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

// Verify signature
function verifySignature(algo, data, signature, cert) {
  const verifier = crypto.createVerify(algo === 'SHA256withRSA' ? 'RSA-SHA256' : algo);
  verifier.update(data, 'utf8');
  return verifier.verify(cert, signature, 'base64');
}

// Fallback
app.use((req, res) => {
  res.status(404).send(`Cannot ${req.method} ${req.originalUrl}`);
});

app.listen(port, () => console.log(`🚀 Listening at http://localhost:${port}`));
