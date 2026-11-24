const express = require('express');
const cors = require('cors');
const app = express();

// Security Misconfiguration: CORS permisivo inseguro con comodin '*'
app.use(cors({ origin: '*', credentials: true }));

app.get('/health', (req, res) => {
    res.json({ status: 'UP', service: 'api-gateway' });
});

app.listen(8080, () => {
    console.log('API Gateway running on port 8080');
});
