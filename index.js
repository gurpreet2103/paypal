const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const https = require('https');

require('dotenv').config();

const app = express();
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
    const body = req.body;

    // Construct expected message
    const expectedSigPayload = `${transmissionId}|${transmissionTime}|${webhookId}|${JSON.stringify(body)}`;

    // Force IPv4 to avoid ECONNREFUSED
    const httpsAgent = new https.Agent({ family: 4 });

    // Download certificate
    const certResponse = await axios.get(certUrl, { httpsAgent });
    const cert = certResponse.data;

    // Verify signature
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(expectedSigPayload, 'utf8');
    const isValid = verifier.verify(cert, transmissionSig, 'base64');

    if (isValid) {
      console.log('Webhook verified successfully.');
      return res.status(200).send('Webhook verified');
    } else {
      console.error('Invalid signature.');
      return res.status(400).send('Invalid signature');
    }
  } catch (error) {
    console.error('Verification failed:', error.message);
    return res.status(500).send('Internal Server Error');
  }
});

app.get('/', (req, res) => {
  res.send('PayPal webhook verification service is live');
});

app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
