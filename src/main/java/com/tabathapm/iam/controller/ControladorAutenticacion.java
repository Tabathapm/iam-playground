package com.tabathapm.iam.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.tabathapm.iam.dto.RespuestaToken;
import com.tabathapm.iam.dto.SolicitudLogin;
import com.tabathapm.iam.service.ServicioAutenticacion;
import com.tabathapm.iam.service.ServicioAutenticacionGoogle;
import com.tabathapm.iam.service.ServicioAutenticacionLDAP;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j; 
import java.io.IOException;

/**
 * Controlador para endpoints de autenticacion: login, refresh, etc.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class ControladorAutenticacion {

    private final ServicioAutenticacion servicioAutenticacion;
    private final ServicioAutenticacionLDAP servicioAutenticacionLDAP;

    @Autowired //Que hace Autowired? Inyecta el servicio de autenticacion Google, 
    // que no se inyecta por constructor porque tiene una logica de negocio mas compleja y no es un simple bean.
    // que es un bean? Es un componente gestionado por Spring, que se instancia y configura automaticamente.
    private ServicioAutenticacionGoogle servicioAutenticacionGoogle;

    /**
     * POST /api/auth/login
     *
     * Body: { "nombreUsuario": "...", "contrasena": "..." }
     *
     * Respuestas:
     *   200 OK con { "token": "...", "tipo": "Bearer", "expiraEnSegundos": 3600 }
     *   401 Unauthorized si las credenciales son invalidas
     *   400 Bad Request si faltan campos (gracias a @Valid + @NotBlank)
     */
    @PostMapping("/login")
    public ResponseEntity<RespuestaToken> login(
            @Valid @RequestBody SolicitudLogin solicitud) {
        return ResponseEntity.ok(servicioAutenticacion.autenticar(solicitud));
    }

    /**
     * Endpoint para autenticación contra LDAP.
     * 
     * Los usuarios se autentican contra OpenLDAP en lugar de PostgreSQL.
     * Si la autenticación es exitosa, se crea/actualiza el usuario en BD local
     * y se devuelve un JWT igual al del login tradicional.
     * 
     * Ejemplo de uso:
     * POST /api/auth/login-ldap
     * {
     *   "nombreUsuario": "tabatha-ldap",
     *   "contrasena": "tabatha-ldap-123"
     * }
     * 
     * Respuestas:
     * - 200 OK con { "token": "...", "tipo": "Bearer", "expiraEnSegundos": 3600 }
     * - 401 Unauthorized si las credenciales LDAP son inválidas
     * - 400 Bad Request si faltan campos
     * 
     */
    @PostMapping("/login-ldap")
    public ResponseEntity<RespuestaToken> loginLDAP(
            @Valid @RequestBody SolicitudLogin solicitud) {
        
        try {
            log.info("Intento de login LDAP: {}", solicitud.nombreUsuario());
            
            String token = servicioAutenticacionLDAP.autenticarContraLDAP(
                solicitud.nombreUsuario(),
                solicitud.contrasena()
            );
            
            log.info("Login LDAP exitoso: {}", solicitud.nombreUsuario());
            
            // RespuestaToken requiere: token, tipo, expiraEnSegundos
            // La duración está en application.properties como iam.jwt.duracion-ms
            long expiraEnSegundos = 3600; // 1 hora (igual que en application.properties: 3600000 ms)
            
            return ResponseEntity.ok(new RespuestaToken(token, "Bearer", expiraEnSegundos));
            
        } catch (RuntimeException e) {
            log.warn("Login LDAP fallido: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new RespuestaToken(null, "Bearer", 0));
        }
    }

     
    // El frontend redirige a Google, el usuario se autentica ahí, y luego Google redirige a este endpoint con un código. 
    // Este endpoint recibe ese código, lo intercambia por tokens de Google, extrae el email, 
    // sincroniza con la BD y devuelve un JWT propio.
    @GetMapping("/google/callback")
    public void googleCallback(@RequestParam String code, HttpServletResponse response) throws IOException {
        try {
            String token = servicioAutenticacionGoogle.autenticar(code);
            response.sendRedirect("http://localhost:8080/dashboard.html?token=" + token);
        } catch (RuntimeException e) {
            response.sendRedirect("http://localhost:8080/login.html?error=unauthorized");
        }
    }
}