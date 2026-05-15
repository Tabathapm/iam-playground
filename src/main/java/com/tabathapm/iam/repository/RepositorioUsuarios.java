package com.tabathapm.iam.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tabathapm.iam.entity.Usuario;

/**
 * Repositorio JPA para la entidad Usuario.
 *
 * Al extender JpaRepository<Usuario, Long> ya heredamos automaticamente:
 *   - findAll()                  -> SELECT * FROM usuarios
 *   - findById(Long id)          -> SELECT * FROM usuarios WHERE id = ?
 *   - save(Usuario u)            -> INSERT o UPDATE segun el estado
 *   - deleteById(Long id)        -> DELETE FROM usuarios WHERE id = ?
 *   - count(), existsById(), etc.
 *
 * Ademas, se agrega metodos "derivados del nombre": Spring Data interpreta el nombre del metodo y genera la query automaticamente. 
 * La sintaxis es:
 *   findBy<Campo>And<OtroCampo>...
 *
 * Se devuelve Optional<Usuario> en lugar de Usuario para forzar el manejo explicito del caso "no existe" sin usar null.
 */
@Repository
public interface RepositorioUsuarios extends JpaRepository<Usuario, Long> {

    Optional<Usuario> findByNombreUsuario(String nombreUsuario);

    Optional<Usuario> findByCorreo(String correo);

    boolean existsByNombreUsuario(String nombreUsuario);

    boolean existsByCorreo(String correo);
}