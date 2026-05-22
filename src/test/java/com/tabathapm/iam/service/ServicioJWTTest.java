package com.tabathapm.iam.service;

import com.tabathapm.iam.entity.Rol;
import com.tabathapm.iam.entity.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ServicioJWTTest {

    private ServicioJWT servicioJWT;
    private Usuario usuarioPrueba;

    // Clave de prueba larga
    private static final String CLAVE_PRUEBA = "clave-secreta-de-prueba-muy-larga-para-testing-iam-playground-1234567890";
    private static final long DURACION_MS = 3_600_000L; // 1 hora

    @BeforeEach //significa: "ejecutá este método antes de cada test"
    void setUp() {
        // Se crea un servicio nuevo antes de cada test (estado limpio)
        servicioJWT = new ServicioJWT(CLAVE_PRUEBA, DURACION_MS);

        // Usuario de prueba
        usuarioPrueba = new Usuario();
        usuarioPrueba.setId(1L);
        usuarioPrueba.setNombreUsuario("tabatha");
        usuarioPrueba.setRoles(Set.of(Rol.ADMINISTRADOR));
    }

    @Test
    @DisplayName("generarToken devuelve un token no nulo con estructura de 3 partes")
    void generarToken_deberiaGenerarTokenConTresPartes() {
        String token = servicioJWT.generarToken(usuarioPrueba);

        assertNotNull(token, "El token no debería ser nulo");
        // Un JWT tiene 3 partes separadas por puntos: header.payload.signature
        assertEquals(3, token.split("\\.").length, "El JWT debe tener 3 partes");
    }

    @Test
    @DisplayName("el subject del token coincide con el nombre de usuario")
    void extraerNombreUsuario_deberiaCoincidirConElUsuario() {
        String token = servicioJWT.generarToken(usuarioPrueba);

        String nombre = servicioJWT.extraerNombreUsuario(token);

        assertEquals("tabatha", nombre);
    }

    @Test
    @DisplayName("el token contiene los roles del usuario en sus claims")
    void validarYExtraerClaims_deberiaContenerLosRoles() {
        String token = servicioJWT.generarToken(usuarioPrueba);

        Claims claims = servicioJWT.validarYExtraerClaims(token);

        // que hace SuppressWarnings("unchecked")? 
        // Es para evitar la advertencia de tipo sin comprobar al leer el claim "roles" como List<String>.
        @SuppressWarnings("unchecked")
        List<String> roles = claims.get("roles", List.class);
        assertNotNull(roles, "El claim 'roles' no debería ser nulo");
        assertTrue(roles.contains("ADMINISTRADOR"), "Debe contener el rol ADMINISTRADOR");
    }

    @Test
    @DisplayName("el token contiene el idUsuario en sus claims")
    void validarYExtraerClaims_deberiaContenerElIdUsuario() {
        String token = servicioJWT.generarToken(usuarioPrueba);

        Claims claims = servicioJWT.validarYExtraerClaims(token);

        // El id se serializa como número en el JSON; lo leemos como Number
        Object idClaim = claims.get("idUsuario");
        assertNotNull(idClaim, "El claim 'idUsuario' no debería ser nulo");
        assertEquals(1L, ((Number) idClaim).longValue());
    }

    @Test
    @DisplayName("esTokenValido devuelve true para un token recién generado")
    void esTokenValido_conTokenValido_deberiaRetornarTrue() {
        String token = servicioJWT.generarToken(usuarioPrueba);

        assertTrue(servicioJWT.esTokenValido(token));
    }

    @Test
    @DisplayName("esTokenValido devuelve false para un string que no es un token")
    void esTokenValido_conTokenBasura_deberiaRetornarFalse() {
        assertFalse(servicioJWT.esTokenValido("esto-no-es.un-token.valido"));
    }

    @Test
    @DisplayName("validarYExtraerClaims rechaza un token firmado con otra clave")
    void validarYExtraerClaims_conTokenDeOtraClave_deberiaLanzarExcepcion() {
        // Un servicio "atacante" con una clave secreta distinta
        ServicioJWT servicioConOtraClave = new ServicioJWT(
                "otra-clave-totalmente-distinta-pero-igual-de-larga-para-testing-9876543210",
                DURACION_MS);
        String tokenAjeno = servicioConOtraClave.generarToken(usuarioPrueba);

        // El servicio (con la clave original) debe rechazarlo:
        // la firma no coincide, por lo que es un token no confiable.
        assertThrows(JwtException.class, () -> servicioJWT.validarYExtraerClaims(tokenAjeno));
    }

    @Test
    @DisplayName("un token expirado no es válido")
    void esTokenValido_conTokenExpirado_deberiaRetornarFalse() throws InterruptedException {
        // Servicio con duración de 1 milisegundo
        ServicioJWT servicioExpiracionCorta = new ServicioJWT(CLAVE_PRUEBA, 1L);
        String token = servicioExpiracionCorta.generarToken(usuarioPrueba);

        // Esperamos a que expire
        Thread.sleep(50);

        assertFalse(servicioExpiracionCorta.esTokenValido(token),
                "Un token expirado no debería ser válido");
    }
}