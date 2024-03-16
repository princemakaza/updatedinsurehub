const express = require('express');
const admin = require('firebase-admin');
const bodyParser = require('body-parser');
const app = express();
var serviceAccount = require("./credentials/package.json");

// Parse JSON bodies
app.use(bodyParser.json());

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
// Route to set custom claims
app.post('/setCustomClaims', async(req, res) => {
    const { token, roles } = req.body;

    try {
        // Verify the user token
        const decodedToken = await admin.auth().verifyIdToken(token);

        // Get existing custom claims
        const userRecord = await admin.auth().getUser(decodedToken.uid);
        const customClaims = userRecord.customClaims || {}; // Check if customClaims is defined

        // Merge existing roles with new roles
        const updatedRoles = Object.assign({}, customClaims.roles || {}, roles);

        // Set custom claims for user roles
        await admin.auth().setCustomUserClaims(decodedToken.uid, { roles: updatedRoles });

        // Send the updated roles as JSON response
        res.status(200).json({ roles: updatedRoles });
    } catch (error) {
        console.error('Error setting custom claims:', error);
        let errorMessage = 'Failed to set custom claims';
        if (error.code === 'auth/argument-error') {
            errorMessage = 'Invalid arguments provided';
        } else if (error.code === 'auth/id-token-expired') {
            errorMessage = 'Token has expired';
        }
        res.status(500).json({ error: errorMessage });
    }
});

app.listen(5000, () => {
    console.log('Server is running on port 5000');
});