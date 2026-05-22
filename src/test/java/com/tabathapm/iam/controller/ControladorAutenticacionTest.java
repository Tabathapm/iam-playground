package com.tabathapm.iam.controller;

import com.tabathapm.iam.service.ServicioJWT;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests de integración para ControladorAutenticacion.
 *
 * @SpringBootTest levanta el contexto Spring completo (BD, servicios, etc).
 * @AutoConfigureMockMvc inyecta MockMvc, que permite hacer requests HTTP en memoria,
 * sin levantar un servidor real. Es el puente entre el test y los endpoints.
 *
 */
@SpringBootTest
@AutoConfigureMockMvc
class ControladorAutenticacionTest {

    @Autowired 
    private MockMvc mockMvc;

    @Autowired
    private ServicioJWT servicioJWT;

    @Test
    @DisplayName("POST /api/auth/login con credenciales válidas devuelve 200 OK y token")
    void login_conCredencialesValidas_devuelve200YToken() throws Exception {
        // Preparación
        String solicitudLogin = """
                {
                    "nombreUsuario": "tabatha",
                    "contrasena": "tabatha123"
                }
                """;

        // Ejecutar y  Afirmar
        MvcResult resultado = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(solicitudLogin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").isNotEmpty())
            .andExpect(jsonPath("$.tipo").value("Bearer"))
            .andExpect(jsonPath("$.expiraEnSegundos").value(3600))
            .andReturn();

        // Verificación extra: extraer el token del response y validarlo
        String responseBody = resultado.getResponse().getContentAsString();
        assertTrue(responseBody.contains("\"token\":"), "El response debe contener un token");
    }

    @Test
    @DisplayName("POST /api/auth/login con contraseña inválida devuelve 401 Unauthorized")
    void login_conContraseñaInvalida_devuelve401() throws Exception {
        String solicitudLogin = """
                {
                    "nombreUsuario": "tabatha",
                    "contrasena": "contrasena-completamente-incorrecta"
                }
                """;

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(solicitudLogin))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /api/auth/login con usuario inexistente devuelve 401")
    void login_conUsuarioInexistente_devuelve401() throws Exception {
        String solicitudLogin = """
                {
                    "nombreUsuario": "usuario-que-no-existe",
                    "contrasena": "alguna-contrasena"
                }
                """;

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(solicitudLogin))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    @DisplayName("POST /api/auth/login-ldap con credenciales LDAP válidas devuelve 200 OK")
    void loginLDAP_conCredencialesValidas_devuelve200YToken() throws Exception {
        String solicitudLogin = """
                {
                    "nombreUsuario": "tabatha-ldap",
                    "contrasena": "tabatha-ldap-123"
                }
                """;

        mockMvc.perform(post("/api/auth/login-ldap")
                .contentType(MediaType.APPLICATION_JSON)
                .content(solicitudLogin))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").isNotEmpty())
            .andExpect(jsonPath("$.tipo").value("Bearer"))
            .andExpect(jsonPath("$.expiraEnSegundos").value(3600));
    }

    @Test
    @DisplayName("POST /api/auth/login-ldap con credenciales LDAP inválidas devuelve 401")
    void loginLDAP_conCredencialesInvalidas_devuelve401() throws Exception {
        String solicitudLogin = """
                {
                    "nombreUsuario": "tabatha-ldap",
                    "contrasena": "contrasena-ldap-incorrecta"
                }
                """;

        mockMvc.perform(post("/api/auth/login-ldap")
                .contentType(MediaType.APPLICATION_JSON)
                .content(solicitudLogin))
            .andExpect(status().isUnauthorized());
    }

    /**
     * El token devuelto por login local es un JWT válido y contiene
     * el nombre del usuario en el claim 'sub' (subject).
     *
     * Este test extrae el token, lo valida y verifica su contenido 
     * Este test es para el login local, que también devuelve JWT.
     */
    @Test
    @DisplayName("El JWT devuelto por login contiene el nombre del usuario")
    void loginYExtraerToken_deberiaContenerNombreEnClaim() throws Exception {
        String solicitudLogin = """
                {
                    "nombreUsuario": "tabatha",
                    "contrasena": "tabatha123"
                }
                """;

        MvcResult resultado = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(solicitudLogin))
            .andExpect(status().isOk())
            .andReturn();

        // Extraer el JSON del response (es un String)
        String responseBody = resultado.getResponse().getContentAsString();

        // Parsear manualmente para extraer el token
        // Response es: {"token":"eyJ...","tipo":"Bearer","expiraEnSegundos":3600}
        String token = extraerTokenDelJson(responseBody);
        assertNotNull(token, "El token no debería ser nulo");
        assertFalse(token.isEmpty(), "El token no debería estar vacío");

        // Validar el token usando ServicioJWT
        assertTrue(servicioJWT.esTokenValido(token), "El token debería ser válido");

        // Extraer claims y verificar el nombre de usuario
        Claims claims = servicioJWT.validarYExtraerClaims(token);
        assertEquals("tabatha", claims.getSubject(), "El subject del token debería ser 'tabatha'");

        // Verificar que contiene los roles
        // que hace SuppressWarnings("unchecked")? 
        // Es para evitar la advertencia de tipo sin comprobar al leer el claim "roles"
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("roles", List.class);
        assertNotNull(roles, "El token debería contener un claim 'roles'");
        assertFalse(roles.isEmpty(), "El usuario debería tener al menos un rol");
    }

    // Para extrae el valor del claim "token" de un JSON response sin agregar dependencias de parsing JSON.
    private String extraerTokenDelJson(String json) {
        String patron = "\"token\":\"";
        int inicio = json.indexOf(patron);
        if (inicio == -1) return null;

        inicio += patron.length();
        int fin = json.indexOf("\"", inicio);
        return json.substring(inicio, fin);
    }
}