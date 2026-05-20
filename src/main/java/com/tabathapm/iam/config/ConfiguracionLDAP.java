package com.tabathapm.iam.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

/**
 * Configuración de Spring LDAP.
 * 
 * Define cómo Spring debe conectarse al servidor OpenLDAP:
 * - URL del servidor (ldap://localhost:389)
 * - Credenciales del usuario técnico (admin)
 * - DN base del directorio
 * 
 * Sin esta clase, Spring no sabe cómo crear el LdapTemplate.
 */
@Configuration
public class ConfiguracionLDAP {

    @Value("${iam.ldap.url}")
    private String ldapUrl;

    @Value("${iam.ldap.usuario-tecnico}")
    private String usuarioTecnico;

    @Value("${iam.ldap.contrasena-tecnico}")
    private String contrasenaTecnico;

    @Value("${iam.ldap.base-dn}")
    private String baseDn;

    /**
     * Crea la fuente de contexto LDAP.
     * 
     * Esto define cómo conectarse al servidor LDAP:
     * - URL
     * - Credenciales del admin/service account
     * - DN base
     */
    @Bean
    public LdapContextSource ldapContextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(ldapUrl);
        contextSource.setUserDn(usuarioTecnico);
        contextSource.setPassword(contrasenaTecnico);
        contextSource.setBase(baseDn);
        contextSource.afterPropertiesSet(); // Importante: inicializa la conexión
        return contextSource;
    }

    /**
     * Crea el LdapTemplate.
     * 
     * Este es el objeto que vas a inyectar en ServicioAutenticacionLDAP.
     * Proporciona métodos como authenticate(), search(), bind(), etc.
     */
    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(ldapContextSource());
    }
}