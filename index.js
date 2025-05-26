const express = require('express');
const crypto = require('crypto');
const https = require('https');
const { URL } = require('url');
const app = express();
const port = process.env.PORT || 3000;

// Your PayPal webhook ID from dashboard
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || 'WH-54M31324A08453805-0TT498265C515724R';

// Middleware to accept ANY content type and capture raw body
app.use('/webhook', express.raw({ 
  type: '*/*',  // Accept any content type
  limit: '10mb'
}));

// Modified endpoint to handle n8n HTTP requests - accepts ANY content type
app.post('/webhook', async (req, res) => {
  try {
    const headers = req.headers;
    const contentType = headers['content-type'] || 'not-specified';
    const rawBody = req.body; // This will be a Buffer
    
    console.log('\n🔔 Received PayPal Webhook from n8n:');
    console.log('Content-Type:', contentType);
    console.log('Raw body type:', typeof rawBody);
    console.log('Raw body length:', rawBody ? rawBody.length : 'undefined');
    console.log('Headers:', JSON.stringify(headers, null, 2));
    
    // Convert buffer to string
    const bodyString = rawBody ? rawBody.toString('utf8') : '';
    console.log('Body as string:', bodyString);
    
    // Try to parse as JSON
    let body;
    try {
      body = JSON.parse(bodyString);
      console.log('✅ Successfully parsed as JSON');
    } catch (e) {
      console.log('❌ Could not parse as JSON, using raw string');
      body = bodyString;
    }
    
    console.log('Final parsed body:', JSON.stringify(body, null, 2));
    console.log('Body type:', typeof body);
    console.log('Body keys:', typeof body === 'object' ? Object.keys(body) : 'not an object');

    // Extract PayPal verification headers
    const transmissionId = headers['paypal-transmission-id'];
    const transmissionTime = headers['paypal-transmission-time'];
    const certUrl = headers['paypal-cert-url'];
    const transmissionSig = headers['paypal-transmission-sig'];
    const authAlgo = headers['paypal-auth-algo'];

    if (!transmissionId || !transmissionTime || !certUrl || !transmissionSig || !authAlgo) {
      console.error('❌ Missing PayPal verification headers');
      return res.status(400).json({ 
        success: false, 
        error: 'Missing PayPal headers',
        received_headers: Object.keys(headers)
      });
    }

    // Get webhook ID - try from environment, then from body, then from headers
    let webhookId = PAYPAL_WEBHOOK_ID;
    if (body.webhook_id) {
      webhookId = body.webhook_id;
    }

    if (!webhookId || webhookId === 'YOUR_PAYPAL_WEBHOOK_ID_HERE') {
      console.error('❌ PayPal webhook ID not found! Please set PAYPAL_WEBHOOK_ID or include in request');
      return res.status(500).json({ 
        success: false, 
        error: 'Webhook ID not configured' 
      });
    }

    // Get the payload - handle different formats from n8n
    let payloadString;
    if (body.data) {
      // If n8n sends {webhook_id: "...", data: {...}}
      payloadString = typeof body.data === 'string' ? body.data : JSON.stringify(body.data);
    } else if (typeof body === 'object' && body !== null) {
      // If n8n sends the webhook payload as an object, stringify it
      payloadString = JSON.stringify(body);
    } else {
      // If it's already a string
      payloadString = body.toString();
    }
    
    // If payloadString looks like just a number, it means we got the wrong data
    if (/^\d+$/.test(payloadString.trim())) {
      console.error('❌ Payload appears to be just a number, not the full webhook JSON');
      console.error('❌ This suggests the webhook body is not being sent correctly from n8n');
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid payload - expected full webhook JSON, got: ' + payloadString,
        hint: 'Check your n8n HTTP node body configuration'
      });
    }

    console.log('📝 Using webhook ID:', webhookId);
    console.log('📝 Payload string length:', payloadString.length);
    console.log('📝 First 200 chars of payload:', payloadString.substring(0, 200));
    console.log('📝 Last 100 chars of payload:', payloadString.substring(payloadString.length - 100));

    // Construct expected signed string PayPal expects: transmissionId|transmissionTime|webhookId|payloadString
    const expectedString = `${transmissionId}|${transmissionTime}|${webhookId}|${payloadString}`;
    
    console.log('🔐 Expected string components:');
    console.log('  - transmissionId:', transmissionId);
    console.log('  - transmissionTime:', transmissionTime);
    console.log('  - webhookId:', webhookId);
    console.log('  - payloadLength:', payloadString.length);
    console.log('🔐 Full expected string length:', expectedString.length);
    console.log('🔐 Expected string (first 300 chars):', expectedString.substring(0, 300));
    
    // Try different payload formatting approaches
    const alternativePayloads = [
      payloadString,
      payloadString.replace(/\s+/g, ''), // Remove all whitespace
      JSON.stringify(JSON.parse(payloadString)), // Re-stringify to normalize
      JSON.stringify(JSON.parse(payloadString), null, 0) // Compact format
    ];
    
    console.log('🔧 Trying multiple payload formats for verification...');

    try {
      // Download the PayPal public certificate
      const certPem = await downloadCertificate(certUrl);
      
      // Try different payload formats to find the one PayPal originally signed
      let isValid = false;
      let workingPayload = null;
      
      for (let i = 0; i < alternativePayloads.length; i++) {
        const testPayload = alternativePayloads[i];
        const testString = `${transmissionId}|${transmissionTime}|${webhookId}|${testPayload}`;
        
        console.log(`🔐 Attempt ${i + 1}: Testing payload format (length: ${testPayload.length})`);
        
        const verified = verifySignature(authAlgo, testString, transmissionSig, certPem);
        if (verified) {
          isValid = true;
          workingPayload = testPayload;
          console.log(`✅ Signature verified with format ${i + 1}!`);
          break;
        }
      }

      if (!isValid) {
        console.error('❌ Invalid signature with all payload formats, rejecting webhook');
        console.error('🔍 Debug info:');
        console.error('  - Cert URL:', certUrl);
        console.error('  - Auth Algo:', authAlgo);
        console.error('  - Transmission Sig length:', transmissionSig.length);
        console.error('  - Webhook ID used:', webhookId);
        
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid signature',
          debug: {
            webhookId,
            transmissionId,
            transmissionTime,
            payloadLength: payloadString.length,
            certUrl,
            authAlgo,
            signatureLength: transmissionSig.length,
            testedFormats: alternativePayloads.length
          }
        });
      }

      console.log('✅ Webhook signature verified successfully!');

      // Parse the actual webhook data for processing
      let webhookData;
      if (body.data) {
        webhookData = typeof body.data === 'string' ? JSON.parse(body.data) : body.data;
      } else {
        webhookData = body;
      }

      console.log('📦 Webhook Event Type:', webhookData.event_type);
      console.log('📦 Resource Type:', webhookData.resource_type);

      // Process the webhook based on event type
      await processWebhookEvent(webhookData);

      return res.status(200).json({ 
        success: true, 
        message: 'Webhook verified and processed',
        event_type: webhookData.event_type 
      });

    } catch (certError) {
      console.error('❌ Certificate download/verification error:', certError);
      return res.status(500).json({ 
        success: false, 
        error: 'Certificate verification failed',
        details: certError.message 
      });
    }

  } catch (err) {
    console.error('❌ Error processing webhook:', err);
    return res.status(500).json({ 
      success: false, 
      error: 'Internal Server Error',
      details: err.message 
    });
  }
});

// Process different webhook events
async function processWebhookEvent(webhookData) {
  const eventType = webhookData.event_type;
  
  console.log(`\n🎯 Processing ${eventType} event`);
  
  switch (eventType) {
    case 'INVOICING.INVOICE.PAID':
      console.log('💰 Invoice paid:', webhookData.resource.invoice.id);
      // Add your invoice paid logic here
      break;
      
    case 'INVOICING.INVOICE.UPDATED':
      console.log('📝 Invoice updated:', webhookData.resource.invoice.id);
      console.log('📝 Status:', webhookData.resource.invoice.status);
      // Add your invoice updated logic here
      break;
      
    case 'INVOICING.INVOICE.CANCELLED':
      console.log('❌ Invoice cancelled:', webhookData.resource.invoice.id);
      // Add your invoice cancelled logic here
      break;
      
    case 'PAYMENT.CAPTURE.COMPLETED':
      console.log('💳 Payment completed:', webhookData.resource.id);
      // Add your payment completed logic here
      break;
      
    default:
      console.log('ℹ️ Unhandled event type:', eventType);
  }
}

// Download certificate helper
function downloadCertificate(certUrl) {
  return new Promise((resolve, reject) => {
    console.log('📜 Downloading certificate from:', certUrl);
    
    https.get(new URL(certUrl), (res) => {
      if (res.statusCode !== 200) {
        return reject(new Error(`Failed to download cert, status code: ${res.statusCode}`));
      }
      
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        console.log('✅ Certificate downloaded successfully');
        resolve(data);
      });
    }).on('error', (err) => {
      console.error('❌ Certificate download error:', err);
      reject(err);
    });
  });
}

// Verify signature helper
function verifySignature(authAlgo, data, signature, cert) {
  const nodeAlgo = authAlgo === 'SHA256withRSA' ? 'RSA-SHA256' : authAlgo;
  
  try {
    console.log('🔐 Verifying signature with algorithm:', nodeAlgo);
    console.log('🔐 Data to verify (first 200 chars):', data.substring(0, 200));
    
    const verifier = crypto.createVerify(nodeAlgo);
    verifier.update(data, 'utf8');
    const verified = verifier.verify(cert, signature, 'base64');
    
    console.log('🔐 Signature verification result:', verified);
    return verified;
  } catch (error) {
    console.error('❌ Signature verification error:', error);
    return false;
  }
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    webhook_id: PAYPAL_WEBHOOK_ID ? 'configured' : 'not_configured'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'PayPal Webhook Verifier',
    endpoints: {
      '/webhook': 'POST - Verify PayPal webhooks from n8n',
      '/health': 'GET - Health check'
    },
    webhook_id_configured: !!PAYPAL_WEBHOOK_ID
  });
});

app.listen(port, () => {
  console.log(`🚀 PayPal Webhook Verifier listening on http://localhost:${port}`);
  console.log(`🔑 Webhook ID configured: ${PAYPAL_WEBHOOK_ID ? 'Yes' : 'No'}`);
});
