package com.tabathapm.iam.service;

import java.util.List;
import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tabathapm.iam.entity.Rol;
import com.tabathapm.iam.entity.Usuario;
import com.tabathapm.iam.repository.RepositorioUsuarios;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Servicio que centraliza la logica de negocio relacionada con usuarios.
 *
 * Esta clase es el "puente" entre los controladores (que manejan HTTP)
 * y el repositorio (que habla con la BD). Aca van todas las reglas:
 * validar duplicados, hashear contrasenas, decidir cuando un usuario
 * puede o no hacer algo, etc.
 *
 * @Service le indica a Spring que esta clase es un bean de tipo servicio,
 *          que se va a inyectar donde haga falta.
 *
 * @RequiredArgsConstructor (Lombok) genera un constructor con TODOS los
 *          campos "final". Spring usa ese constructor para inyectar las
 *          dependencias automaticamente (inyeccion por constructor, la
 *          forma recomendada hoy en dia).
 *
 * @Slf4j genera un logger "log" que usamos para loguear eventos.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ServicioUsuarios {

    private final RepositorioUsuarios repositorioUsuarios;
    private final PasswordEncoder codificadorContrasena;

    /**
     * Crea un nuevo usuario en el sistema.
     *
     * Pasos:
     *   1. Validar que el nombre de usuario no este en uso.
     *   2. Validar que el correo no este en uso.
     *   3. Hashear la contrasena con BCrypt.
     *   4. Persistir el usuario.
     *
     * @Transactional asegura que TODO esto ocurra dentro de una unica
     * transaccion: si algo falla a la mitad, se hace rollback automatico.
     */
    @Transactional
    public Usuario crearUsuario(
            String nombreUsuario,
            String correo,
            String contrasenaEnTextoPlano,
            Rol... roles) {

        if (repositorioUsuarios.existsByNombreUsuario(nombreUsuario)) {
            throw new IllegalArgumentException(
                "Ya existe un usuario con el nombre: " + nombreUsuario);
        }
        if (repositorioUsuarios.existsByCorreo(correo)) {
            throw new IllegalArgumentException(
                "Ya existe un usuario con el correo: " + correo);
        }

        Usuario nuevoUsuario = Usuario.builder()
            .nombreUsuario(nombreUsuario)
            .correo(correo)
            .hashContrasena(codificadorContrasena.encode(contrasenaEnTextoPlano))
            .activo(true)
            .build();

        // Agregar los roles recibidos
        for (Rol rol : roles) {
            nuevoUsuario.getRoles().add(rol);
        }

        Usuario guardado = repositorioUsuarios.save(nuevoUsuario);
        log.info("Usuario creado: id={}, nombreUsuario={}, roles={}",
                guardado.getId(), guardado.getNombreUsuario(), guardado.getRoles());
        return guardado;
    }

    /**
     * Devuelve todos los usuarios.
     * @Transactional(readOnly=true) optimiza la transaccion para solo lectura.
     */
    @Transactional(readOnly = true)
    public List<Usuario> listarTodos() {
        return repositorioUsuarios.findAll();
    }

    /**
     * Busca un usuario por su nombre de usuario (para el login).
     */
    @Transactional(readOnly = true)
    public Optional<Usuario> buscarPorNombreUsuario(String nombreUsuario) {
        return repositorioUsuarios.findByNombreUsuario(nombreUsuario);
    }

    /**
     * Busca un usuario por su id.
     */
    @Transactional(readOnly = true)
    public Optional<Usuario> buscarPorId(Long id) {
        return repositorioUsuarios.findById(id);
    }
}