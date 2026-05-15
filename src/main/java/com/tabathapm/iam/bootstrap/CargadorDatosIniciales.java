package com.tabathapm.iam.bootstrap;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.tabathapm.iam.entity.Rol;
import com.tabathapm.iam.repository.RepositorioUsuarios;
import com.tabathapm.iam.service.ServicioUsuarios;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class CargadorDatosIniciales implements CommandLineRunner {

    private final ServicioUsuarios servicioUsuarios;
    private final RepositorioUsuarios repositorioUsuarios;

    @Override
    public void run(String... args) {
        if (repositorioUsuarios.count() > 0) {
            log.info("La BD ya tiene usuarios cargados ({}). No se cargan datos iniciales.",
                    repositorioUsuarios.count());
            return;
        }

        log.info("BD vacia. Creando usuarios iniciales de prueba...");

        servicioUsuarios.crearUsuario(
            "tabatha", "tabathapm@gmail.com", "tabatha123", Rol.ADMINISTRADOR);
        servicioUsuarios.crearUsuario(
            "juan", "juan@acme.com", "juan123", Rol.USUARIO);
        servicioUsuarios.crearUsuario(
            "auditor", "auditor@acme.com", "auditor123", Rol.AUDITOR);

        log.info("Datos iniciales cargados correctamente.");
    }
}