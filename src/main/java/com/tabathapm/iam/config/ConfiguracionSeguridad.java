package com.tabathapm.iam.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.tabathapm.iam.security.FiltroAutenticacionJWT;

import lombok.RequiredArgsConstructor;

/**
 * Configuracion central de Spring Security.
 *
 * Aca se declara:
 *   1. Que algoritmo de hashing usamos (BCrypt) - bean PasswordEncoder
 *   2. Que componente carga usuarios (DaoAuthenticationProvider con UserDetailsService)
 *   3. El AuthenticationManager (orquestador de la autenticacion)
 *   4. La cadena de filtros (SecurityFilterChain) que define:
 *      - Que rutas son publicas
 *      - Que rutas requieren autenticacion
 *      - Como se maneja la sesion (stateless)
 *      - Donde se inserta el filtro JWT custom
 */
@Configuration
@EnableMethodSecurity  
@RequiredArgsConstructor
public class ConfiguracionSeguridad {

    private final FiltroAutenticacionJWT filtroJWT;
    private final UserDetailsService servicioDetalleUsuarios;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Provider que une UserDetailsService + PasswordEncoder para hacer
     * la validacion clasica de username/password contra la BD.
     *
     * Desde Spring Security 6.4, el UserDetailsService se pasa por constructor
     * y el PasswordEncoder se setea con el metodo nuevo.
     */
    @Bean
    public DaoAuthenticationProvider proveedorAutenticacion() {
        DaoAuthenticationProvider proveedor =
                new DaoAuthenticationProvider(servicioDetalleUsuarios);
        proveedor.setPasswordEncoder(passwordEncoder());
        return proveedor;
    }

    /**
     * El AuthenticationManager: recibe una solicitud de autenticacion y la pasa por los providers configurados 
     * (aca, solo el DaoAuthenticationProvider).
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuracion) throws Exception {
        return configuracion.getAuthenticationManager();
    }

    /**
     * La cadena de filtros de seguridad.
     *
     * Decisiones tomadas:
     *   - CSRF deshabilitado: solo tiene sentido en apps con sesion en cookies, aca JWT en headers, no aplica.
     *   - Sesion STATELESS: el servidor NO mantiene sesiones. Cada request debe traer su propio JWT. Es la esencia de JWT auth.
     *   - Rutas publicas: /api/auth/** (login, registro futuro), /api/salud
     *   - Todo lo demas: requiere autenticacion
     *   - El FiltroJWT se inserta ANTES del filtro de username/password estandar de Spring Security.
     */
    @Bean
    public SecurityFilterChain cadenaDeFiltros(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/salud").permitAll()
                .anyRequest().authenticated()
            )
            .authenticationProvider(proveedorAutenticacion())
            .addFilterBefore(filtroJWT, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
}