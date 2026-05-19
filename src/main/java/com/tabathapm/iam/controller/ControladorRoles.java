package com.tabathapm.iam.controller;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;

import lombok.RequiredArgsConstructor;

/**
* Si el usuario autenticado no tiene el rol requerido, Spring Security devuelve error 403 Forbidden.
* 403 Forbidden: El usuario autenticado no tiene el rol requerido para acceder a este endpoint. 
* Para manejar esto, se pueden usar anotaciones como @PreAuthorize("hasRole('ADMIN')") en los endpoints que requieren ciertos roles.
*
* Se usa Map porque esto es solo para aprender, pero en una app real hay que usar DTOs para definir claramente la estructura de la respuesta JSON.
*
*/

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ControladorRoles {

    @GetMapping("/admin/panel")
    @PreAuthorize("hasRole('ADMINISTRADOR')")
    public Map<String, String> panelAdmin(Authentication autenticacion) {
        return Map.of(
            "mensaje", "Bienvenido al panel de administración",
            "usuario", autenticacion.getName(),
            "rolRequerido", "ADMINISTRADOR"
        );
    }

    @GetMapping("/usuario/perfil")
    @PreAuthorize("hasAnyRole('USUARIO', 'ADMINISTRADOR')")
    public Map<String, String> perfilUsuario(Authentication autenticacion){
        return Map.of(
            "mensaje", "Bienvenido a tu perfil",
            "usuario", autenticacion.getName(),
            "rolRequerido", "USUARIO o ADMINISTRADOR"
        );
    }

    @GetMapping("/auditor/logs")
    @PreAuthorize("hasRole('AUDITOR')")
    public Map<String, String> logsAuditor(Authentication autenticacion){
        return Map.of(
            "mensaje", "Bienvenido al panel de auditoría",
            "usuario", autenticacion.getName(),
            "rolRequerido", "AUDITOR"
        );
    }

    
}
