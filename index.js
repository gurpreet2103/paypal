const crypto = require('crypto');
const axios = require('axios');

// PayPal Webhook Signature Verification - FIXED VERSION
async function verifyPayPalWebhook(req, webhookId) {
    try {
        // Get headers - handle case variations
        const headers = req.headers;
        const authAlgo = headers['paypal-auth-algo'] || headers['PAYPAL-AUTH-ALGO'];
        const transmission_id = headers['paypal-transmission-id'] || headers['PAYPAL-TRANSMISSION-ID'];
        const cert_id = headers['paypal-cert-id'] || headers['PAYPAL-CERT-ID'];
        const transmission_sig = headers['paypal-transmission-sig'] || headers['PAYPAL-TRANSMISSION-SIG'];
        const transmission_time = headers['paypal-transmission-time'] || headers['PAYPAL-TRANSMISSION-TIME'];
        
        console.log('🔍 Headers received:', {
            authAlgo,
            transmission_id,
            cert_id,
            transmission_sig,
            transmission_time
        });
        
        // Validate required headers
        if (!authAlgo || !transmission_id || !cert_id || !transmission_sig || !transmission_time) {
            console.log('❌ Missing required headers');
            return false;
        }
        
        // Get raw body - this is CRITICAL
        let rawBody;
        if (typeof req.body === 'string') {
            rawBody = req.body;
        } else if (Buffer.isBuffer(req.body)) {
            rawBody = req.body.toString('utf8');
        } else {
            // If body is parsed JSON, we need the raw string
            rawBody = JSON.stringify(req.body);
        }
        
        console.log('📄 Raw body length:', rawBody.length);
        
        // Get PayPal certificate
        const certUrl = `https://api.paypal.com/v1/notifications/certs/${cert_id}`;
        console.log('🔑 Fetching cert from:', certUrl);
        
        const certResponse = await axios.get(certUrl);
        const publicKey = certResponse.data;
        
        // Create the signed message - EXACT format required
        const signedMessage = `${transmission_id}|${transmission_time}|${webhookId}|${crypto.createHash('sha256').update(rawBody, 'utf8').digest('base64')}`;
        
        console.log('🔐 Signed message:', signedMessage);
        
        // Verify signature
        const verifier = crypto.createVerify('SHA256');
        verifier.update(signedMessage, 'utf8');
        
        // Decode base64 signature
        const signature = Buffer.from(transmission_sig, 'base64');
        
        const isValid = verifier.verify(publicKey, signature);
        
        console.log(isValid ? '✅ Signature valid' : '❌ Invalid signature');
        
        return isValid;
        
    } catch (error) {
        console.error('🚨 Webhook verification error:', error.message);
        return false;
    }
}

// Express.js middleware for raw body capture
function rawBodyMiddleware(req, res, next) {
    if (req.headers['content-type'] === 'application/json') {
        let data = '';
        req.setEncoding('utf8');
        req.on('data', (chunk) => {
            data += chunk;
        });
        req.on('end', () => {
            req.rawBody = data;
            try {
                req.body = JSON.parse(data);
            } catch (e) {
                req.body = data;
            }
            next();
        });
    } else {
        next();
    }
}

// Main webhook handler
async function handlePayPalWebhook(req, res) {
    const webhookId = 'WH-54M31324A08453805-0TT498265C515724R'; // Replace with your actual webhook ID
    
    console.log('🎯 PayPal webhook received');
    console.log('📋 Event type:', req.body?.event_type);
    
    // Use raw body for verification
    const bodyForVerification = req.rawBody || JSON.stringify(req.body);
    
    // Create a modified request object for verification
    const verificationReq = {
        headers: req.headers,
        body: bodyForVerification
    };
    
    // Verify webhook signature
    const isValid = await verifyPayPalWebhook(verificationReq, webhookId);
    
    if (!isValid) {
        console.log('❌ Invalid signature, rejecting event');
        return res.status(400).json({ error: 'Invalid signature' });
    }
    
    console.log('✅ Webhook verified successfully');
    
    // Process the webhook event
    const eventType = req.body.event_type;
    
    switch (eventType) {
        case 'INVOICING.INVOICE.PAID':
            console.log('💰 Invoice paid:', req.body.resource.id);
            // Handle paid invoice
            break;
            
        case 'INVOICING.INVOICE.CANCELLED':
            console.log('❌ Invoice cancelled:', req.body.resource.id);
            // Handle cancelled invoice
            break;
            
        case 'INVOICING.INVOICE.CREATED':
            console.log('📄 Invoice created:', req.body.resource.id);
            // Handle created invoice
            break;
            
        default:
            console.log('ℹ️ Unhandled event type:', eventType);
    }
    
    res.status(200).json({ status: 'success' });
}

// N8N specific implementation
function n8nPayPalWebhook() {
    return {
        async webhook(context) {
            const req = context.getRequestObject();
            const res = context.getResponseObject();
            
            const webhookId = 'WH-54M31324A08453805-0TT498265C515724R'; // Set in N8N credentials/settings
            
            // Get raw body
            const rawBody = context.getBodyData()?.raw || JSON.stringify(context.getBodyData());
            
            const verificationReq = {
                headers: req.headers,
                body: rawBody
            };
            
            const isValid = await verifyPayPalWebhook(verificationReq, webhookId);
            
            if (!isValid) {
                res.status(400).json({ error: 'Invalid signature' });
                return;
            }
            
            // Return the webhook data for further processing in N8N
            return {
                workflowData: [
                    [
                        {
                            json: context.getBodyData()
                        }
                    ]
                ]
            };
        }
    };
}

// Common issues and solutions:
/*
1. RAW BODY ISSUE: 
   - PayPal signature verification requires the EXACT raw body
   - If Express parses JSON, the signature will fail
   - Always capture raw body before parsing

2. WEBHOOK ID:
   - Must match exactly what you configured in PayPal
   - Get it from PayPal Developer Dashboard > Webhooks

3. HEADERS CASE:
   - Some servers lowercase headers
   - Check both cases in code

4. CERTIFICATE CACHING:
   - Consider caching certificates for performance
   - They don't change often

5. TIMEZONE ISSUES:
   - Ensure transmission_time is used as-is
   - Don't convert timezones

6. HASH ENCODING:
   - Body hash must be base64 encoded SHA256
   - Signature must be base64 decoded before verification
*/

module.exports = {
    verifyPayPalWebhook,
    handlePayPalWebhook,
    rawBodyMiddleware,
    n8nPayPalWebhook
};
