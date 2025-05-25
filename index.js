const getRawBody = require('raw-body');
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const https = require('https');
require('dotenv').config();

const app = express();

// Middleware to get raw body as string
app.use((req, res, next) => {
  getRawBody(req, {
    length: req.headers['content-length'],
    limit: '1mb',
    encoding: true,
  }, (err, string) => {
    if (err) return next(err);
    req.rawBody = string;
    next();
  });
});

// Now parse json normally (after rawBody middleware)
app.use(express.json());

const PORT = process.env.PORT || 10000;

app.post('/webhook', async (req, res) => {
  try {
    const transmissionId = req.header('paypal-transmission-id');
    const transmissionTime = req.header('paypal-transmission-time');
    const certUrl = req.header('paypal-cert-url');
    const authAlgo = req.header('paypal-auth-algo');
    const transmissionSig = req.header('paypal-transmission-sig');
    const webhookId = process.env.PAYPAL_WEBHOOK_ID;

    if (!webhookId) {
      console.error('❌ PAYPAL_WEBHOOK_ID is not set');
      return res.status(500).send('Webhook ID missing from server config');
    }

    if (!certUrl) {
      console.error('❌ Missing paypal-cert-url header');
      return res.status(400).send('Missing paypal-cert-url header');
    }

    // Use rawBody here, NOT JSON.stringify(req.body)
    const expectedSigPayload = `${transmissionId}|${transmissionTime}|${webhookId}|${req.rawBody}`;

    const httpsAgent = new https.Agent({ family: 4 });

    let cert;
    try {
      const certResponse = await axios.get(certUrl, { httpsAgent });
      cert = certResponse.data;
    } catch (err) {
      console.error('❌ Failed to download certificate:', err.message);
      return res.status(500).send('Failed to fetch certificate');
    }

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(expectedSigPayload, 'utf8');
    const isValid = verifier.verify(cert, transmissionSig, 'base64');

    if (isValid) {
      console.log('✅ Webhook verified successfully.');
      return res.status(200).send('Webhook verified');
    } else {
      console.error('❌ Invalid signature.');
      return res.status(400).send('Invalid signature');
    }

  } catch (err) {
    console.error('🔥 Unexpected error:', err.message);
    return res.status(500).send('Internal Server Error');
  }
});

app.get('/', (req, res) => {
  res.send('PayPal webhook verification server is live.');
});

app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
