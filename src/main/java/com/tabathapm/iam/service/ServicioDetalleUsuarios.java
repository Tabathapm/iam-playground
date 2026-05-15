package com.tabathapm.iam.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.tabathapm.iam.repository.RepositorioUsuarios;

import lombok.RequiredArgsConstructor;

/**
 * Implementacion de UserDetailsService para que Spring Security
 * sepa como cargar usuarios desde la BD.
 *
 * Spring Security llama a loadUserByUsername() durante el proceso
 * de autenticacion: nuestro AuthenticationManager toma el username
 * y la password de la request, este servicio devuelve el UserDetails
 * (con su hash de password guardado), y Spring Security compara
 * usando el PasswordEncoder configurado.
 */
@Service
@RequiredArgsConstructor
public class ServicioDetalleUsuarios implements UserDetailsService {

    private final RepositorioUsuarios repositorioUsuarios;

    @Override
    public UserDetails loadUserByUsername(String nombreUsuario) {
        return repositorioUsuarios.findByNombreUsuario(nombreUsuario)
                .map(AdaptadorUsuarioSpring::new)
                .orElseThrow(() -> new UsernameNotFoundException(
                    "No existe el usuario: " + nombreUsuario));
    }
}