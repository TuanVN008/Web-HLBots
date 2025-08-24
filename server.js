const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://yourdomain.com'] 
        : ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files
app.use(express.static('public'));

// Package configurations
const PACKAGES = {
    'basic': { 
        name: 'Basic Package',
        windows: 3, 
        days: 30, 
        price: 16,
        level: '1',
        features: ['3 Game Windows', '30 Days Support', 'Basic Features', 'Discord Support']
    },
    'pro': { 
        name: 'Pro Package',
        windows: 6, 
        days: 60, 
        price: 23,
        level: '2',
        features: ['6 Game Windows', '60 Days Support', 'Advanced Features', 'Priority Support', 'Auto Update']
    },
    'enterprise': { 
        name: 'Enterprise Package',
        windows: 999, 
        days: 365, 
        price: 45,
        level: '3',
        features: ['Unlimited Windows', '365 Days Support', 'All Features', 'Custom Scripts', 'Dedicated Support']
    }
};

// In-memory storage (Replace with database in production)
global.pendingPayments = {};
global.completedPayments = {};

// API clients
const nowpaymentsAPI = axios.create({
    baseURL: process.env.NOWPAYMENTS_SANDBOX === 'true' 
        ? 'https://api-sandbox.nowpayments.io/v1' 
        : 'https://api.nowpayments.io/v1',
    headers: {
        'x-api-key': process.env.NOWPAYMENTS_API_KEY,
        'Content-Type': 'application/json'
    }
});

// Utility functions
function generateOrderId() {
    return 'GB_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5).toUpperCase();
}

function logPayment(action, paymentId, data = {}) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] Payment ${action}: ${paymentId}`, data);
}

function validatePackage(packageType) {
    return PACKAGES.hasOwnProperty(packageType);
}

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Get available packages
app.get('/api/packages', (req, res) => {
    res.json(PACKAGES);
});

// Create payment invoice
app.post('/api/create-payment', async (req, res) => {
    try {
        const { package: packageType, customer_email } = req.body;
        
        // Validate input
        if (!validatePackage(packageType)) {
            return res.status(400).json({ 
                error: 'Invalid package type',
                available: Object.keys(PACKAGES)
            });
        }

        if (!customer_email || !customer_email.includes('@')) {
            return res.status(400).json({ 
                error: 'Valid email address required' 
            });
        }

        const packageConfig = PACKAGES[packageType];
        const orderId = generateOrderId();

        // Create NOWPayments invoice
        const invoiceData = {
            price_amount: packageConfig.price,
            price_currency: 'USD',
            pay_currency: '', // Let user choose
            order_id: orderId,
            order_description: `${packageConfig.name} - ${packageConfig.windows} windows for ${packageConfig.days} days`,
            ipn_callback_url: `${process.env.BASE_URL}/api/payment-callback`,
            success_url: `${process.env.BASE_URL}/?payment=success`,
            cancel_url: `${process.env.BASE_URL}/?payment=cancelled`
        };

        // Add sandbox parameter if in development
        if (process.env.NOWPAYMENTS_SANDBOX === 'true') {
            invoiceData.case = 'test';
        }

        const response = await nowpaymentsAPI.post('/invoice', invoiceData);
        
        // Store payment info
        const paymentInfo = {
            id: response.data.id,
            order_id: orderId,
            packageType,
            amount: packageConfig.price,
            customer_email,
            status: 'waiting',
            created_at: new Date().toISOString(),
            package_config: packageConfig
        };

        global.pendingPayments[response.data.id] = paymentInfo;
        logPayment('CREATED', response.data.id, { orderId, packageType, amount: packageConfig.price });

        res.json({
            payment_id: response.data.id,
            invoice_url: response.data.invoice_url,
            order_id: orderId
        });

    } catch (error) {
        console.error('Payment creation error:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to create payment',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Check payment status
app.get('/api/payment-status/:paymentId', async (req, res) => {
    try {
        const paymentId = req.params.paymentId;
        const paymentInfo = global.pendingPayments[paymentId] || global.completedPayments[paymentId];
        
        if (!paymentInfo) {
            return res.status(404).json({ error: 'Payment not found' });
        }

        // Check with NOWPayments API
        const response = await nowpaymentsAPI.get(`/payment/${paymentId}`);
        const paymentStatus = response.data.payment_status;

        logPayment('STATUS_CHECK', paymentId, { status: paymentStatus });

        if (paymentStatus === 'finished' && paymentInfo.status !== 'completed') {
            // Payment confirmed - generate license
            try {
                const licenseKey = await generateLicenseKey(paymentInfo);
                
                // Move to completed payments
                paymentInfo.status = 'completed';
                paymentInfo.license_key = licenseKey;
                paymentInfo.completed_at = new Date().toISOString();
                
                global.completedPayments[paymentId] = paymentInfo;
                delete global.pendingPayments[paymentId];

                logPayment('COMPLETED', paymentId, { license_key: licenseKey });
                
                return res.json({
                    status: 'finished',
                    license_key: licenseKey,
                    package_info: paymentInfo.package_config
                });
            } catch (licenseError) {
                console.error('License generation failed:', licenseError);
                return res.status(500).json({ 
                    status: 'error',
                    error: 'Payment confirmed but license generation failed. Please contact support.' 
                });
            }
        }

        res.json({ 
            status: paymentStatus,
            order_id: paymentInfo.order_id,
            created_at: paymentInfo.created_at
        });

    } catch (error) {
        console.error('Payment status check error:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to check payment status',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// NOWPayments IPN callback
app.post('/api/payment-callback', (req, res) => {
    try {
        // Verify signature
        const receivedSignature = req.get('x-nowpayments-sig');
        const payload = JSON.stringify(req.body);
        
        if (process.env.NOWPAYMENTS_IPN_SECRET) {
            const expectedSignature = crypto
                .createHmac('sha512', process.env.NOWPAYMENTS_IPN_SECRET)
                .update(payload)
                .digest('hex');
            
            if (receivedSignature !== expectedSignature) {
                console.error('Invalid IPN signature');
                return res.status(400).send('Invalid signature');
            }
        }

        const { payment_id, payment_status, order_id } = req.body;
        logPayment('IPN_RECEIVED', payment_id, { payment_status, order_id });
        
        if (payment_status === 'finished') {
            const paymentInfo = global.pendingPayments[payment_id];
            
            if (paymentInfo && paymentInfo.status !== 'completed') {
                // Generate license key asynchronously
                generateLicenseKey(paymentInfo)
                    .then(licenseKey => {
                        paymentInfo.status = 'completed';
                        paymentInfo.license_key = licenseKey;
                        paymentInfo.completed_at = new Date().toISOString();
                        
                        global.completedPayments[payment_id] = paymentInfo;
                        delete global.pendingPayments[payment_id];
                        
                        logPayment('AUTO_COMPLETED', payment_id, { license_key: licenseKey });
                    })
                    .catch(error => {
                        console.error('Auto license generation failed:', error);
                        paymentInfo.status = 'payment_confirmed_license_pending';
                    });
            }
        }
        
        res.status(200).send('OK');
    } catch (error) {
        console.error('IPN callback error:', error);
        res.status(500).send('Error processing callback');
    }
});

// Generate license key with KeyAuth
async function generateLicenseKey(paymentInfo) {
    try {
        const packageConfig = paymentInfo.package_config;
        const expiry = Math.floor(Date.now() / 1000) + (packageConfig.days * 24 * 60 * 60);
        
        const keyData = new URLSearchParams({
            type: 'add',
            name: process.env.KEYAUTH_NAME,
            ownerid: process.env.KEYAUTH_OWNERID,
            secret: process.env.KEYAUTH_SECRET,
            expiry: expiry.toString(),
            mask: 'XXXX-XXXX-XXXX-XXXX',
            level: packageConfig.level,
            note: `${paymentInfo.customer_email} - ${packageConfig.name} - ${paymentInfo.order_id}`
        });

        const response = await keyauthAPI.post('', keyData);
        
        if (response.data.success) {
            return response.data.key;
        } else {
            throw new Error(`KeyAuth error: ${response.data.message}`);
        }
    } catch (error) {
        console.error('KeyAuth license generation error:', error.response?.data || error.message);
        throw error;
    }
}

// Validate license (for bot clients)
app.post('/api/validate-license', async (req, res) => {
    try {
        const { license_key, hwid } = req.body;
        
        if (!license_key || !hwid) {
            return res.status(400).json({ 
                valid: false, 
                message: 'License key and HWID required' 
            });
        }
        
        const validationData = new URLSearchParams({
            type: 'login',
            name: process.env.KEYAUTH_NAME,
            ownerid: process.env.KEYAUTH_OWNERID,
            secret: process.env.KEYAUTH_SECRET,
            key: license_key,
            hwid: hwid
        });

        const response = await keyauthAPI.post('', validationData);
        
        if (response.data.success) {
            const level = parseInt(response.data.info.level);
            const packageType = Object.keys(PACKAGES).find(key => PACKAGES[key].level === level.toString());
            
            res.json({
                valid: true,
                windows: PACKAGES[packageType]?.windows || level,
                expires: response.data.info.expires,
                subscription: response.data.info.subscription,
                package: packageType
            });
        } else {
            res.json({ 
                valid: false, 
                message: response.data.message 
            });
        }
    } catch (error) {
        console.error('License validation error:', error.response?.data || error.message);
        res.status(500).json({ 
            valid: false, 
            message: 'Validation service unavailable' 
        });
    }
});

// Serve main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 GameBot Store server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV}`);
    console.log(`💰 NOWPayments Sandbox: ${process.env.NOWPAYMENTS_SANDBOX}`);
    console.log(`🔑 KeyAuth App: ${process.env.KEYAUTH_NAME}`);
});