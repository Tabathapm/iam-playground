package com.tabathapm.iam.service;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.tabathapm.iam.entity.Usuario;

import lombok.RequiredArgsConstructor;

/**
 * Adaptador entre la entidad Usuario y la interfaz UserDetails que Spring Security espera consumir.
 *
 * Este es un ejemplo clasico del patron Adapter: tomamos un objeto de nuestro dominio (Usuario) y le damos la interfaz que un sistema
 * externo (Spring Security) necesita.
 *
 * Nota sobre los roles: Spring Security espera autoridades con prefijo
 * "ROLE_". Por convencion, internamente las llamamos "ADMINISTRADOR",
 * "USUARIO", "AUDITOR" y aca le agregamos el prefijo para que Spring
 * Security las reconozca correctamente.
 */
@RequiredArgsConstructor
public class AdaptadorUsuarioSpring implements UserDetails {

    private final Usuario usuarioInterno;

    public Usuario getUsuarioInterno() {
        return usuarioInterno;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return usuarioInterno.getRoles().stream()
                .map(rol -> new SimpleGrantedAuthority("ROLE_" + rol.name()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return usuarioInterno.getHashContrasena();
    }

    @Override
    public String getUsername() {
        return usuarioInterno.getNombreUsuario();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return usuarioInterno.isActivo();
    }
}