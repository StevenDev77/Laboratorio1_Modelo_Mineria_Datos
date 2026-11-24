package com.espe.product;

import org.springframework.web.bind.annotation.*;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

@RestController
@RequestMapping("/api/v1/products")
public class ProductController {

    private Connection conn;

    // Vulnerabilidad SQL Injection (OWASP A05:2025, CWE-89)
    // Concatenación directa de variable en sentencia SQL sin parámetros preparados
    @GetMapping("/search")
    public String searchProduct(@RequestParam String name) throws Exception {
        String query = "SELECT * FROM products WHERE name = '" + name + "' AND status = 'ACTIVE'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return "Found products";
    }

    // Vulnerabilidad Missing Function Level Authorization (OWASP A01:2025, OWASP API API5:2023, CWE-862)
    // Endpoint administrativo crítico sin anotación de seguridad @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/admin-purge-catalog")
    public void purgeCatalog() {
        // Missing @PreAuthorize("hasRole('ADMIN')")
        catalogService.purgeAll();
    }

    // Endpoint Seguro de Referencia (PreparedStatement)
    @GetMapping("/secure-search")
    public String searchProductSecure(@RequestParam String name) throws Exception {
        String sql = "SELECT * FROM products WHERE name = ? AND status = ?";
        var ps = conn.prepareStatement(sql);
        ps.setString(1, name);
        ps.setString(2, "ACTIVE");
        var rs = ps.executeQuery();
        return "Secure search result";
    }
}
