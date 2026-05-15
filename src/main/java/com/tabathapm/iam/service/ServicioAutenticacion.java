package com.tabathapm.iam.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.tabathapm.iam.dto.RespuestaToken;
import com.tabathapm.iam.dto.SolicitudLogin;
import com.tabathapm.iam.entity.Usuario;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Servicio que orquesta el proceso de login.
 *
 * Pasos:
 *   1. Delegamos la validacion de credenciales al AuthenticationManager
 *      de Spring Security. Ese manager usa nuestro ServicioDetalleUsuarios
 *      + el PasswordEncoder para verificar.
 *   2. Si la autenticacion es exitosa, generamos un JWT para el usuario.
 *   3. Devolvemos el token al cliente.
 *
 * Si las credenciales son invalidas, el AuthenticationManager lanza
 * una BadCredentialsException que se propaga hacia arriba.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ServicioAutenticacion {

    private final AuthenticationManager gestorAutenticacion;
    private final ServicioJWT servicioJWT;

    @Value("${iam.jwt.duracion-ms}")
    private long duracionMs;

    public RespuestaToken autenticar(SolicitudLogin solicitud) {
        // Paso 1: Spring Security valida las credenciales
        Authentication autenticacion = gestorAutenticacion.authenticate(
            new UsernamePasswordAuthenticationToken(
                solicitud.nombreUsuario(),
                solicitud.contrasena()
            )
        );

        // Paso 2: Si se llegó aca, las credenciales eran validas.
        // Extraemos el usuario y generamos el token.
        AdaptadorUsuarioSpring detalle =
                (AdaptadorUsuarioSpring) autenticacion.getPrincipal();
        Usuario usuario = detalle.getUsuarioInterno();

        String token = servicioJWT.generarToken(usuario); 
        log.info("Login exitoso para usuario: {}", usuario.getNombreUsuario());

        return RespuestaToken.bearer(token, duracionMs / 1000); 
    }
}