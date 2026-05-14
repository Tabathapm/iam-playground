package com.tabathapm.iam.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tabathapm.iam.dto.UsuarioDTO;

/**
 * Por ahora trabaja con una lista hardcodeada en memoria.
 */

@RestController
@RequestMapping("/api/usuarios")
public class ControladorUsuarios {

    /**
     * Lista temporal de usuarios en memoria.
     * Los tres usuarios tienen roles distintos (ADMINISTRADOR, USUARIO,
     * AUDITOR) que nos van a servir en la Fase 3 cuando implementemos
     * el control de acceso basado en roles (RBAC).
     */
    private static final List<UsuarioDTO> USUARIOS = List.of(
        new UsuarioDTO(1L, "tabatha", "tabathapm@gmail.com", List.of("ADMINISTRADOR")),
        new UsuarioDTO(2L, "juan",    "juan@acme.com",       List.of("USUARIO")),
        new UsuarioDTO(3L, "auditor", "auditor@acme.com",    List.of("AUDITOR"))
    );

    /**
     * Responde a GET /api/usuarios
     * Devuelve la lista completa de usuarios.
     */
    @GetMapping
    public List<UsuarioDTO> listarUsuarios() {
        return USUARIOS;
    }

    /**
     * Responde a GET /api/usuarios/{id}
     *
     * Busca un usuario por su id. Si lo encuentra devuelve 200 OK
     * con el usuario; si no, devuelve 404 Not Found.
     *
     * Usamos ResponseEntity (en vez de devolver UsuarioDTO directo)
     * porque queremos controlar el código de estado HTTP de la respuesta.
     */
    @GetMapping("/{id}")
    public ResponseEntity<UsuarioDTO> obtenerUsuario(@PathVariable Long id) {
        return USUARIOS.stream()
            .filter(u -> u.id().equals(id))
            .findFirst()
            .map(ResponseEntity::ok)                    // Si lo encuentra → 200 con el usuario
            .orElse(ResponseEntity.notFound().build()); // Si no → 404 sin cuerpo
    }
}