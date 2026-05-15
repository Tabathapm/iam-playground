package com.tabathapm.iam.entity;

public enum Rol {

    /**
     * Acceso total: crear, editar, borrar usuarios y configuraciones.
     */
    ADMINISTRADOR,

    /**
     * Usuario regular: puede ver y editar su propia informacion.
     */
    USUARIO,

    /**
     * Solo lectura sobre los logs de auditoria.
     */
    AUDITOR
}