package com.tabathapm.iam.service;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.tabathapm.iam.entity.Rol;
import com.tabathapm.iam.entity.Usuario;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

/**
 * Servicio responsable de generar y validar JWTs (JSON Web Tokens).
 *
 * Un JWT es un string firmado criptograficamente que contiene "claims"
 * (afirmaciones) sobre el usuario. El cliente lo guarda y lo envia
 * en cada request, y el servidor lo valida sin necesidad de mantener
 * estado de sesion ("stateless authentication").
 *
 * Usamos la libreria JJWT (io.jsonwebtoken), que es la mas popular
 * para Java.
 */
@Service
@Slf4j
public class ServicioJWT {

    /**
     * Clave usada para firmar y verificar los tokens.
     * Se inicializa en el constructor a partir de la propiedad
     * iam.jwt.clave-secreta del application.properties.
     */
    private final SecretKey claveDeFirma;

    /**
     * Duracion de los tokens en milisegundos.
     */
    private final long duracionMs;

    /**
     * Constructor: Spring inyecta las propiedades via @Value.
     *
     * Convertimos la clave string a SecretKey aplicandole un encoding
     * adecuado para HS256.
     */
    public ServicioJWT(
            @Value("${iam.jwt.clave-secreta}") String claveSecreta,
            @Value("${iam.jwt.duracion-ms}") long duracionMs) {

        // La clave debe tener al menos 256 bits para HS256.
        // Codificamos los bytes del string directamente.
        byte[] bytesClave = claveSecreta.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        this.claveDeFirma = Keys.hmacShaKeyFor(bytesClave);
        this.duracionMs = duracionMs;
    }

    /**
     * Genera un JWT para un usuario autenticado.
     *
     * Claims incluidos:
     *   - sub: nombre de usuario
     *   - roles: lista de roles
     *   - iat: cuando se emitio
     *   - exp: cuando expira
     *
     * @param usuario el usuario para el que se emite el token
     * @return el JWT como String
     */
    public String generarToken(Usuario usuario) {
        Instant ahora = Instant.now();
        Instant expiracion = ahora.plusMillis(duracionMs);

        // Convertir los roles del enum a Strings para serializarlos
        List<String> rolesComoStrings = usuario.getRoles().stream()
                .map(Rol::name)
                .toList();

        String token = Jwts.builder()
                .subject(usuario.getNombreUsuario())
                .claim("roles", rolesComoStrings)
                .claim("idUsuario", usuario.getId())
                .issuedAt(Date.from(ahora))
                .expiration(Date.from(expiracion))
                .signWith(claveDeFirma)
                .compact();

        log.debug("Token generado para usuario {} (expira en {} ms)",
                usuario.getNombreUsuario(), duracionMs);
        return token;
    }

    /**
     * Valida un token. Si es valido devuelve los Claims (payload decodificado).
     * Si NO es valido (firma incorrecta, expirado, malformado, etc),
     * lanza una excepcion JwtException.
     *
     * Esta validacion verifica:
     *   - Que la firma sea correcta (no fue modificado)
     *   - Que no este expirado
     *   - Que la estructura sea valida
     */
    public Claims validarYExtraerClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(claveDeFirma)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException ex) {
            log.warn("Token JWT invalido: {}", ex.getMessage());
            throw ex;
        }
    }

    /**
     * Extrae el nombre de usuario del subject del token.
     */
    public String extraerNombreUsuario(String token) {
        return validarYExtraerClaims(token).getSubject();
    }

    /**
     * Verifica si un token es valido sin lanzar excepcion.
     * Util para flujos donde solo queres saber "si o no".
     */
    public boolean esTokenValido(String token) {
        try {
            validarYExtraerClaims(token);
            return true;
        } catch (JwtException ex) {
            return false;
        }
    }
}