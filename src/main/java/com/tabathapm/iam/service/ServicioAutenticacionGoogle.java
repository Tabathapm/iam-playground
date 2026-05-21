package com.tabathapm.iam.service;

import com.tabathapm.iam.entity.Rol;
import com.tabathapm.iam.entity.Usuario;
import com.tabathapm.iam.repository.RepositorioUsuarios;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

@Service
public class ServicioAutenticacionGoogle {

    @Value("${iam.google.client-id}")
    private String clientId;

    @Value("${iam.google.client-secret}")
    private String clientSecret;

    @Value("${iam.google.redirect-uri}")
    private String redirectUri;

    @Value("${iam.google.token-uri}")
    private String tokenUri;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private RepositorioUsuarios repositorioUsuarios;

    @Autowired
    private ServicioJWT servicioJWT;

    /**
     * Autentica al usuario intercambiando el authorization code por tokens de
     * Google,
     * extrayendo su email y sincronizando con la BD.
     */
    public String autenticar(String codigo) {
        try {
            // 1. Intercambiar código por tokens de Google
            Map<String, Object> tokens = intercambiarCodigoXTokens(codigo);
            String idToken = (String) tokens.get("id_token");

            // 2. Extraer email del ID token
            String email = extraerEmailDelIdToken(idToken);

            // 3. Sincronizar o crear usuario en PostgreSQL
            Usuario usuario = obtenerOCrearUsuarioGoogle(email);

            // 4. Generar JWT propio
            return servicioJWT.generarToken(usuario);
        } catch (Exception e) {
            throw new RuntimeException("Error al autenticar con Google: " + e.getMessage(), e);
        }
    }

    /**
     * Intercambia el authorization code por access_token e id_token.
     * Realiza una petición POST al Google token endpoint.
     */
    private Map<String, Object> intercambiarCodigoXTokens(String codigo) {
        try {
            // Configurar headers para application/x-www-form-urlencoded
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            // Construir body con parámetros requeridos
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("code", codigo);
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("redirect_uri", redirectUri);
            body.add("grant_type", "authorization_code");

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            // POST al token endpoint de Google
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, request, Map.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            } else {
                throw new RuntimeException("Google token endpoint retornó: " + response.getStatusCode());
            }
        } catch (Exception e) {
            throw new RuntimeException("Error intercambiando código con Google: " + e.getMessage(), e);
        }
    }

    private String extraerEmailDelIdToken(String idToken) {
        try {
            // JWT tiene 3 partes separadas por puntos: header.payload.signature
            String[] partes = idToken.split("\\.");
            if (partes.length != 3) {
                throw new RuntimeException("ID token inválido: no tiene 3 partes");
            }

            // Decodificar payload (parte 2) desde Base64 URL-safe
            byte[] decodedBytes = Base64.getUrlDecoder().decode(partes[1]);
            String payloadJson = new String(decodedBytes, StandardCharsets.UTF_8);

            // Extraer el email del JSON con un parseo simple
            String email = extraerCampoJson(payloadJson, "email");
            if (email == null || email.isEmpty()) {
                throw new RuntimeException("No se encontró email en el ID token");
            }

            return email;
        } catch (Exception e) {
            throw new RuntimeException("Error extrayendo email del ID token: " + e.getMessage(), e);
        }
    }

    /**
     * Extrae el valor de un campo string de un JSON simple.
     * Busca "campo":"valor" y devuelve el valor.
     * Acá se se hace un parseo casero, pero en producción se debería usar una librería.
     */
    private String extraerCampoJson(String json, String campo) {
        String busqueda = "\"" + campo + "\"";
        int indiceClavePos = json.indexOf(busqueda);
        if (indiceClavePos == -1) {
            return null;
        }
        // Buscar los dos puntos después de la clave
        int indiceDosPuntos = json.indexOf(":", indiceClavePos + busqueda.length());
        if (indiceDosPuntos == -1) {
            return null;
        }
        // Buscar la primera comilla del valor
        int inicioValor = json.indexOf("\"", indiceDosPuntos);
        if (inicioValor == -1) {
            return null;
        }
        // Buscar la comilla de cierre del valor
        int finValor = json.indexOf("\"", inicioValor + 1);
        if (finValor == -1) {
            return null;
        }
        return json.substring(inicioValor + 1, finValor);
    }

    /**
     * Obtiene el usuario de la BD o lo crea si no existe (just-in-time
     * provisioning).
     * El username se deriva del email (parte anterior a @).
     */
    private Usuario obtenerOCrearUsuarioGoogle(String email) {
        return repositorioUsuarios.findByCorreo(email)
                .orElseGet(() -> {
                    Usuario usuarioNuevo = new Usuario();
                    // Usar la parte del email antes de @ como nombre de usuario
                    String nombreUsuario = email.split("@")[0];
                    usuarioNuevo.setNombreUsuario(nombreUsuario);
                    usuarioNuevo.setCorreo(email);
                    // No tiene contraseña, viene de Google
                    usuarioNuevo.setHashContrasena("");
                    usuarioNuevo.setActivo(true);
                    // Por defecto, rol USUARIO
                    usuarioNuevo.setRoles(Set.of(Rol.USUARIO));
                    usuarioNuevo.setFechaCreacion(Instant.now());

                    return repositorioUsuarios.save(usuarioNuevo);
                });
    }
}