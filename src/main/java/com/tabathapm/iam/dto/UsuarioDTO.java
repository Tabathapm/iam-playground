package com.tabathapm.iam.dto;

import java.util.List;

/**
 * DTO (Data Transfer Object) que representa un usuario tal como
 * se muestra hacia afuera de la API.
 *
 * Importante: este objeto NO incluye campos sensibles.
 *
 * Se usa un "record" de Java: genera automáticamente
 * constructor, getters, equals, hashCode y toString.
 * Ideal para DTOs porque son inmutables por naturaleza.
 */
public record UsuarioDTO(
    Long id,
    String nombreUsuario,
    String correo,
    List<String> roles
) {}