package com.tabathapm.iam.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * DTO para la solicitud de login.
 *
 * Las anotaciones @NotBlank son de Bean Validation: si el cliente envia
 * uno de los campos vacio o null, Spring rechaza la peticion con 400
 * automaticamente antes de llegar al controller.
 */
public record SolicitudLogin(
    @NotBlank(message = "El nombre de usuario es obligatorio")
    String nombreUsuario,

    @NotBlank(message = "La contrasena es obligatoria")
    String contrasena
) {}