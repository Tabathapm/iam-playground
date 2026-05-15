package com.tabathapm.iam.entity;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Importante: aca SI guardamos el hash de la contrasena (nunca en texto plano)
 * porque esta es la representacion interna del usuario. Hacia afuera siempre exponemos UsuarioDTO, que NO incluye la contrasena.
 */
@Entity
@Table(name = "usuarios")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "nombre_usuario", nullable = false, unique = true, length = 50)
    private String nombreUsuario;

    @Column(name = "correo", nullable = false, unique = true, length = 120)
    private String correo;

    /**
     * Hash BCrypt de la contrasena.
     * NUNCA contiene texto plano. BCrypt genera hashes de 60 caracteres,
     * por eso length=72 (con un poco de margen).
     */
    @Column(name = "hash_contrasena", nullable = false, length = 72)
    private String hashContrasena;

    @Column(name = "activo", nullable = false)
    @Builder.Default
    private boolean activo = true;

    /**
     * Roles asignados al usuario. Un usuario puede tener varios roles
     * (por ejemplo, ADMINISTRADOR y AUDITOR a la vez).
     *
     * @ElementCollection crea una tabla aparte "usuarios_roles" con dos
     * columnas: usuario_id y rol. 
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "usuarios_roles",
        joinColumns = @JoinColumn(name = "usuario_id")
    )
    @Column(name = "rol", length = 30)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Set<Rol> roles = new HashSet<>();

    @Column(name = "fecha_creacion", nullable = false, updatable = false)
    private Instant fechaCreacion;

    /**
     * Hook de JPA: se ejecuta justo antes del primer INSERT.
     * Sirve para inicializar campos calculados como timestamps.
     */
    @jakarta.persistence.PrePersist
    protected void alCrear() {
        this.fechaCreacion = Instant.now();
    }
}