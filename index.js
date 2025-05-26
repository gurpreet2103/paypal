const express = require('express');
const crypto = require('crypto');
const https = require('https');
const { URL } = require('url');

const app = express();
const port = process.env.PORT || 3000;

// Your PayPal webhook ID from dashboard
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || 'WH-54M31324A08453805-0TT498265C515724R';

// Use express.raw() to capture raw body as a Buffer (no JSON parsing here!)
app.post('/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const headers = req.headers;
    const rawBodyBuffer = req.body; // Buffer containing exact bytes PayPal sent
    const rawBodyString = rawBodyBuffer.toString('utf8'); // EXACT raw string

    // Log raw payload string and headers for debugging
    console.log('\n🔔 Received PayPal Webhook:');
    console.log('Headers:', headers);
    console.log('Raw body:', rawBodyString);

    // Extract PayPal verification headers
    const transmissionId = headers['paypal-transmission-id'];
    const transmissionTime = headers['paypal-transmission-time'];
    const certUrl = headers['paypal-cert-url'];
    const transmissionSig = headers['paypal-transmission-sig'];
    const authAlgo = headers['paypal-auth-algo'];

    if (!transmissionId || !transmissionTime || !certUrl || !transmissionSig || !authAlgo) {
      console.error('❌ Missing PayPal verification headers');
      return res.status(400).send('Missing PayPal headers');
    }

    if (!PAYPAL_WEBHOOK_ID || PAYPAL_WEBHOOK_ID === 'YOUR_PAYPAL_WEBHOOK_ID_HERE') {
      console.error('❌ PayPal webhook ID not set! Please set PAYPAL_WEBHOOK_ID');
      return res.status(500).send('Webhook ID not configured');
    }

    // Construct expected signed string PayPal expects: transmissionId|transmissionTime|webhookId|rawBodyString
    const expectedString = `${transmissionId}|${transmissionTime}|${PAYPAL_WEBHOOK_ID}|${rawBodyString}`;

    // Download the PayPal public certificate
    const certPem = await downloadCertificate(certUrl);

    // Verify the signature using Node crypto
    const isValid = verifySignature(authAlgo, expectedString, transmissionSig, certPem);

    if (!isValid) {
      console.error('❌ Invalid signature, rejecting webhook');
      return res.status(400).send('Invalid signature');
    }

    console.log('✅ Webhook signature verified successfully!');

    // If you want to parse JSON for further processing after verifying signature:
    const jsonBody = JSON.parse(rawBodyString);
    console.dir(jsonBody, { depth: null });

    return res.status(200).send('Webhook verified');
  } catch (err) {
    console.error('❌ Error processing webhook:', err);
    return res.status(500).send('Internal Server Error');
  }
});

// Download certificate helper
function downloadCertificate(certUrl) {
  return new Promise((resolve, reject) => {
    https.get(new URL(certUrl), (res) => {
      if (res.statusCode !== 200) {
        return reject(new Error(`Failed to download cert, status code: ${res.statusCode}`));
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

// Verify signature helper
function verifySignature(authAlgo, data, signature, cert) {
  const nodeAlgo = authAlgo === 'SHA256withRSA' ? 'RSA-SHA256' : authAlgo;
  try {
    const verifier = crypto.createVerify(nodeAlgo);
    verifier.update(data, 'utf8');
    const verified = verifier.verify(cert, signature, 'base64');
    console.log('🔐 Signature valid:', verified);
    return verified;
  } catch (error) {
    console.error('❌ Signature verification error:', error);
    return false;
  }
}

app.listen(port, () => {
  console.log(`🚀 Webhook server listening on http://localhost:${port}`);
});
