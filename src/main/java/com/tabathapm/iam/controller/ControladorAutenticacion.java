package com.tabathapm.iam.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tabathapm.iam.dto.RespuestaToken;
import com.tabathapm.iam.dto.SolicitudLogin;
import com.tabathapm.iam.service.ServicioAutenticacion;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

/**
 * Controlador para endpoints de autenticacion: login, refresh, etc.
 * Por ahora solo tenemos login.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class ControladorAutenticacion {

    private final ServicioAutenticacion servicioAutenticacion;

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
}