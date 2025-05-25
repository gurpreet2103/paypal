const express = require('express');
const crypto = require('crypto');
const https = require('https');
const { promisify } = require('util');

const app = express();
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf; // Save raw body buffer for signature verification
  }
}));

// Helper: Fetch certificate from PayPal
function fetchCertificate(certUrl) {
  return new Promise((resolve, reject) => {
    https.get(certUrl, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

// PayPal Webhook Verification
app.post('/paypal-webhook', async (req, res) => {
  try {
    const headers = req.headers;

    const transmissionId = headers['paypal-transmission-id'];
    const transmissionTime = headers['paypal-transmission-time'];
    const certUrl = headers['paypal-cert-url'];
    const authAlgo = headers['paypal-auth-algo'];
    const transmissionSig = headers['paypal-transmission-sig'];
    const webhookId = 'WH-54M31324A08453805-0TT498265C515724R'; // Replace with your actual PayPal webhook ID
    const rawBody = req.rawBody.toString('utf8');

    // Build expected signed string
    const expectedSignatureString = [
      transmissionId,
      transmissionTime,
      webhookId,
      crypto.createHash('sha256').update(rawBody, 'utf8').digest('hex')
    ].join('|');

    // Download PayPal public certificate
    const certPem = await fetchCertificate(certUrl);

    // Verify signature
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(expectedSignatureString);
    verifier.end();

    const signatureIsValid = verifier.verify(certPem, transmissionSig, 'base64');

    if (!signatureIsValid) {
      console.error('⚠️ Invalid PayPal signature');
      return res.status(400).send('Invalid signature');
    }

    // ✅ Signature valid: proceed
    console.log('✅ Verified PayPal webhook:', req.body);
    res.sendStatus(200);
  } catch (err) {
    console.error('❌ Error verifying PayPal webhook:', err);
    res.sendStatus(500);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
