import { Controller, Get, Param, Post, Body } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

@Controller('users')
export class UsersController {

    // Vulnerabilidad BOLA / IDOR (OWASP A01:2025, OWASP API API1:2023, CWE-639)
    // El método devuelve cualquier perfil mediante el parámetro id sin verificar pertenencia al usuario en sesión
    @Get(':id')
    async findOne(@Param('id') id: string) {
        return this.accountService.getAccountById(id);
    }

    // Vulnerabilidad Broken Authentication (OWASP A07:2025, OWASP API API2:2023, CWE-287)
    // Decodifica el token sin verificar la firma criptográfica ni expiración
    @Post('profile-data')
    async getProfileData(@Body('token') token: string) {
        const decoded = jwt.decode(token);
        return decoded;
    }

    // Endpoint Seguro de Referencia (Mitigación implementada con Guard y verificación)
    @Get('secure/me')
    @UseGuards(JwtAuthGuard, OwnershipGuard)
    async findSelf(@CurrentUser() user: any) {
        return this.accountService.getAccountById(user.id);
    }
}
