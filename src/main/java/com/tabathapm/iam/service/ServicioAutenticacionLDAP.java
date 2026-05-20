package com.tabathapm.iam.service;

import com.tabathapm.iam.entity.Rol;
import com.tabathapm.iam.entity.Usuario;
import com.tabathapm.iam.repository.RepositorioUsuarios;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * Servicio de autenticación contra OpenLDAP.
 * 
 * Realiza "bind authentication": conecta como admin, busca el usuario,
 * intenta segundo bind con las credenciales ingresadas.
 * Si tiene éxito, crea/actualiza el usuario en PostgreSQL y devuelve JWT.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ServicioAutenticacionLDAP {

    private final LdapTemplate ldapTemplate;
    private final RepositorioUsuarios repositorioUsuarios;
    private final ServicioJWT servicioJWT;

    @Value("${iam.ldap.base-busqueda-usuarios}")
    private String baseOu;  // "ou=personas"

    @Value("${iam.ldap.base-dn}")
    private String baseDn;  // "dc=tabathapm,dc=local"

    /**
     * Autentica un usuario contra LDAP y devuelve un JWT.
     * 
     * Proceso:
     * 1. Intenta bind authentication contra LDAP
     * 2. Si tiene éxito: crea/actualiza el usuario en BD local
     * 3. Genera JWT con datos del usuario
     * 4. Devuelve el token
     * 
     * @param nombreUsuario El uid del usuario (ej: "tabatha-ldap")
     * @param contrasena    La contraseña en texto plano
     * @return JWT token si la autenticación es exitosa
     * @throws RuntimeException si la autenticación falla
     */
    public String autenticarContraLDAP(String nombreUsuario, String contrasena) {
        log.info("Intentando autenticar usuario LDAP: {}", nombreUsuario);

        try {
            // BIND AUTHENTICATION contra LDAP
            // Parámetros:
            // 1. base: DN base donde buscar (ej: ou=personas,dc=tabathapm,dc=local)
            // 2. filter: filtro LDAP para encontrar al usuario (ej: uid=tabatha-ldap)
            // 3. password: la contraseña en texto plano
            
            String baseDeBusqueda = "ou=" + baseOu;
            String filtro = "(uid=" + nombreUsuario + ")";
            
            ldapTemplate.authenticate(baseDeBusqueda, filtro, contrasena);

            log.info("Autenticación LDAP exitosa para: {}", nombreUsuario);

            // Si llegamos aquí, la autenticación fue exitosa.
            // Ahora: crear o actualizar el usuario en PostgreSQL
            Usuario usuario = obtenerOCrearUsuarioLDAP(nombreUsuario);

            // Generar JWT con datos del usuario
            // Nota: generarToken() solo recibe el nombreUsuario, no los roles separados
            String token = servicioJWT.generarToken(usuario);

            log.info("Token generado para usuario LDAP: {}", nombreUsuario);
            return token;

        } catch (org.springframework.ldap.AuthenticationException e) {
            log.warn("Autenticación LDAP fallida para: {} — {}", nombreUsuario, e.getMessage());
            throw new RuntimeException("Credenciales LDAP inválidas", e);
        } catch (Exception e) {
            log.error("Error inesperado en autenticación LDAP: {}", e.getMessage(), e);
            throw new RuntimeException("Error en autenticación LDAP", e);
        }
    }

    /**
     * Obtiene o crea un usuario en PostgreSQL basado en datos de LDAP.
     * 
     * Por simplicidad:
     * - Si el usuario no existe, lo crea con rol USUARIO
     * - Si existe, lo devuelve tal cual
     * 
     * En producción, esto sería más sofisticado:
     * - Sincronización de grupos LDAP a roles
     * - Mapeo de atributos más complejo
     * - Auditoría de cambios
     */
    private Usuario obtenerOCrearUsuarioLDAP(String nombreUsuario) {
        log.debug("Buscando usuario LDAP en BD local: {}", nombreUsuario);

        // Buscar si ya existe
        return repositorioUsuarios.findByNombreUsuario(nombreUsuario)
            .orElseGet(() -> {
                log.info("Usuario LDAP no existe en BD local, creando: {}", nombreUsuario);
                
                // Crear nuevo usuario
                Usuario usuarioNuevo = new Usuario();
                usuarioNuevo.setNombreUsuario(nombreUsuario);
                
                // El correo lo generamos a partir del nombreUsuario
                // (en producción, lo traerías del atributo 'mail' del LDAP)
                usuarioNuevo.setCorreo(nombreUsuario + "@tabathapm.local");
                
                // No guardamos contraseña de usuarios LDAP
                // (la contraseña se valida contra LDAP, no contra BD local)
                usuarioNuevo.setHashContrasena("");
                
                // Usuario activo
                usuarioNuevo.setActivo(true);
                
                // Rol por defecto: USUARIO
                Set<Rol> rolesDefault = new HashSet<>();
                rolesDefault.add(Rol.USUARIO);
                usuarioNuevo.setRoles(rolesDefault);
                
                // Fecha de creación
                usuarioNuevo.setFechaCreacion(Instant.now());

                // Guardar en BD
                Usuario guardado = repositorioUsuarios.save(usuarioNuevo);
                log.info("Usuario LDAP creado en BD local: {}", nombreUsuario);
                
                return guardado;
            });
    }
}