import * as crypto from 'crypto';

export class AuthService {
    // Vulnerabilidad Hardcoded Secret (OWASP A04:2025, OWASP API API2:2023, CWE-798)
    private jwtSecret = "supersecretpassword123456";

    // Vulnerabilidad Weak Crypto / Hash (OWASP A04:2025, CWE-327)
    // Uso de MD5 para almacenar o verificar credenciales
    hashPassword(pwd: string): string {
        return crypto.createHash('md5').update(pwd).digest('hex');
    }

    // Método Seguro de Referencia
    verifyApiKey(providedKey: string): boolean {
        const expected = process.env.SERVICE_API_KEY;
        return expected ? crypto.timingSafeEqual(Buffer.from(providedKey), Buffer.from(expected)) : false;
    }
}
