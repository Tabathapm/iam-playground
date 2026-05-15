package com.tabathapm.iam.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.tabathapm.iam.service.ServicioDetalleUsuarios;
import com.tabathapm.iam.service.ServicioJWT;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Filtro que se ejecuta UNA vez por request (OncePerRequestFilter).
 *
 * Trabajo del filtro:
 *   1. Buscar el header "Authorization: Bearer <token>"
 *   2. Si esta, extraer el JWT y validarlo via ServicioJWT
 *   3. Si es valido, cargar el UserDetails y autenticar en el SecurityContext
 *   4. Pasar la request al siguiente filtro de la cadena
 *
 * Si el token falta o es invalido, por el momento NO se bloque aca
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class FiltroAutenticacionJWT extends OncePerRequestFilter {

    private final ServicioJWT servicioJWT;
    private final ServicioDetalleUsuarios servicioDetalleUsuarios;

    private static final String CABECERA_AUTORIZACION = "Authorization";
    private static final String PREFIJO_BEARER = "Bearer ";

    @Override
    protected void doFilterInternal(
            HttpServletRequest peticion,
            HttpServletResponse respuesta,
            FilterChain cadena) throws ServletException, IOException {

        String token = extraerToken(peticion);

        if (token != null) {
            try {
                Claims claims = servicioJWT.validarYExtraerClaims(token);
                String nombreUsuario = claims.getSubject();

                // Si todavia no hay autenticacion en el contexto, la seteamos
                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails detalleUsuario = servicioDetalleUsuarios
                            .loadUserByUsername(nombreUsuario);

                    // Se crea el "objeto autenticacion" de Spring Security:
                    // - principal: los datos del usuario
                    // - credentials: null (ya validamos via JWT, no necesitamos pass)
                    // - authorities: roles del usuario
                    UsernamePasswordAuthenticationToken autenticacion =
                        new UsernamePasswordAuthenticationToken(
                            detalleUsuario,
                            null,
                            detalleUsuario.getAuthorities()
                        );
                    autenticacion.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(peticion));

                    SecurityContextHolder.getContext().setAuthentication(autenticacion);
                    log.debug("Autenticacion JWT establecida para usuario: {}", nombreUsuario);
                }
            } catch (JwtException ex) {
                log.warn("Token JWT invalido en request a {}: {}",
                        peticion.getRequestURI(), ex.getMessage());
                // No se bloquea aca: dejamos que el resto de la cadena decida.
            }
        }

        cadena.doFilter(peticion, respuesta);
    }

    /**
     * Extrae el JWT del header "Authorization: Bearer <token>".
     * Devuelve null si el header no esta o no tiene el formato esperado.
     */
    private String extraerToken(HttpServletRequest peticion) {
        String headerAuth = peticion.getHeader(CABECERA_AUTORIZACION);
        if (headerAuth != null && headerAuth.startsWith(PREFIJO_BEARER)) {
            return headerAuth.substring(PREFIJO_BEARER.length());
        }
        return null;
    }
}