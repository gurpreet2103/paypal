const express = require('express');
const crypto = require('crypto');
const https = require('https');
const { URL } = require('url');

const app = express();
const port = process.env.PORT || 3000;

// === IMPORTANT: Put your PayPal webhook ID here ===
// You get this from your PayPal developer dashboard when you create your webhook
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || 'WH-54M31324A08453805-0TT498265C515724R';

// Only raw body for webhook so signature check works correctly
app.post('/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const headers = req.headers;
    const rawBody = req.body; // Buffer
    const bodyString = rawBody.toString('utf8'); // Must be unaltered exact string

    const transmissionId = headers['paypal-transmission-id'];
    const transmissionTime = headers['paypal-transmission-time'];
    const certUrl = headers['paypal-cert-url'];
    const transmissionSig = headers['paypal-transmission-sig'];
    const authAlgo = headers['paypal-auth-algo'];

    console.log('\n🔔 Webhook received');
    console.log('Headers:', headers);
    console.log('Raw body:', bodyString);

    if (!transmissionId || !transmissionTime || !certUrl || !transmissionSig || !authAlgo) {
      console.error('❌ Missing PayPal verification headers');
      return res.status(400).send('Missing PayPal headers');
    }

    if (!PAYPAL_WEBHOOK_ID || PAYPAL_WEBHOOK_ID === 'YOUR_PAYPAL_WEBHOOK_ID_HERE') {
      console.error('❌ PayPal webhook ID not set! Please set PAYPAL_WEBHOOK_ID');
      return res.status(500).send('Webhook ID not configured');
    }

    // Construct the expected signed string including webhook ID (critical)
    const expectedString = `${transmissionId}|${transmissionTime}|${PAYPAL_WEBHOOK_ID}|${bodyString}`;

    console.log('\n🔍 Verification details:');
    console.log('expectedString:', expectedString);
    console.log('certUrl:', certUrl);
    console.log('authAlgo:', authAlgo);
    console.log('signature:', transmissionSig);

    let certPem;
    try {
      certPem = await downloadCertificate(certUrl);
      console.log('✅ Certificate downloaded');
    } catch (err) {
      console.error('❌ Failed to download certificate:', err.message);
      return res.status(400).send('Certificate download failed');
    }

    const isValid = verifySignature(authAlgo, expectedString, transmissionSig, certPem);

    if (!isValid) {
      console.error('❌ Invalid signature');
      return res.status(400).send('Invalid signature');
    }

    console.log('✅ Webhook verified!');
    const parsedBody = JSON.parse(bodyString);
    console.dir(parsedBody, { depth: null });

    return res.status(200).send('Verified');
  } catch (err) {
    console.error('❌ Error in webhook handler:', err);
    return res.status(500).send('Internal Server Error');
  }
});

// Download cert
function downloadCertificate(certUrl) {
  return new Promise((resolve, reject) => {
    https.get(new URL(certUrl), (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        if (res.statusCode !== 200) {
          return reject(new Error(`Bad status: ${res.statusCode}`));
        }
        resolve(data);
      });
    }).on('error', reject);
  });
}

// Verify PayPal signature
function verifySignature(algo, data, signature, cert) {
  const nodeAlgo = algo === 'SHA256withRSA' ? 'RSA-SHA256' : algo;
  try {
    const verifier = crypto.createVerify(nodeAlgo);
    verifier.update(data, 'utf8');
    const result = verifier.verify(cert, signature, 'base64');
    console.log('🔐 Signature valid:', result);
    return result;
  } catch (err) {
    console.error('❌ Verification error:', err.message);
    return false;
  }
}

// Fallback route
app.use((req, res) => {
  res.status(404).send(`Cannot ${req.method} ${req.originalUrl}`);
});

app.listen(port, () => {
  console.log(`🚀 Server listening at http://localhost:${port}`);
});
