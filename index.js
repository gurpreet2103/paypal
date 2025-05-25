const express = require('express');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(express.json({ type: '*/*' })); // Ensure raw body is parsed

app.post('/webhook', async (req, res) => {
  const transmissionId = req.header('paypal-transmission-id');
  const timeStamp = req.header('paypal-transmission-time');
  const webhookId = process.env.PAYPAL_WEBHOOK_ID;
  const certUrl = req.header('paypal-cert-url');
  const actualSig = req.header('paypal-transmission-sig');
  const authAlgo = req.header('paypal-auth-algo');
  const body = JSON.stringify(req.body);

  const expectedSignature = await verifySignature({
    transmissionId,
    timeStamp,
    webhookId,
    body,
    certUrl,
    authAlgo,
    actualSig,
  });

  if (expectedSignature) {
    console.log('✅ Verified');
    res.sendStatus(200);
  } else {
    console.log('❌ Verification failed');
    res.sendStatus(400);
  }
});

const verifySignature = ({ transmissionId, timeStamp, webhookId, body, certUrl, authAlgo, actualSig }) => {
  return new Promise((resolve, reject) => {
    https.get(certUrl, (res) => {
      let cert = '';
      res.on('data', (chunk) => cert += chunk);
      res.on('end', () => {
        const expectedSigString = `${transmissionId}|${timeStamp}|${webhookId}|${crypto.createHash('sha256').update(body, 'utf8').digest('hex')}`;
        const verifier = crypto.createVerify(authAlgo);
        verifier.update(expectedSigString);
        verifier.end();

        const isValid = verifier.verify(cert, actualSig, 'base64');
        resolve(isValid);
      });
    }).on('error', reject);
  });
};

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
