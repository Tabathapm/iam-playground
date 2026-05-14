# IAM Playground

Proyecto personal de aprendizaje sobre **Identity & Access Management (IAM)**.
Implementación progresiva, fase por fase, de los conceptos centrales que componen
un sistema de gestión de identidades y accesos.

## Objetivos de aprendizaje

- Autenticación local con JSON Web Tokens (JWT)
- Autorización basada en roles (RBAC)
- Integración con servicio de directorio (OpenLDAP)
- Federación de identidad con OAuth 2.0 / OpenID Connect (Google)
- Auditoría de eventos de seguridad
- Documentación OpenAPI / Swagger

## Stack técnico

| Capa | Tecnología |
|------|------------|
| Lenguaje | Java 21 |
| Framework | Spring Boot 4.0.6 |
| Seguridad | Spring Security 6 |
| Persistencia | PostgreSQL 16 (Docker) |
| Directorio | OpenLDAP (Docker) |
| Build | Maven (Wrapper incluido) |
| Utilidades | Lombok |

## Roadmap

- [x] **Fase 1** — Scaffolding inicial: endpoints `/api/salud` y `/api/usuarios` con datos en memoria.
- [ ] **Fase 2** — Autenticación local con JWT + PostgreSQL.
- [ ] **Fase 3** — Autorización por roles (RBAC).
- [ ] **Fase 4** — Integración con OpenLDAP.
- [ ] **Fase 5** — Login con Google (OAuth 2.0 / OIDC).
- [ ] **Fase 6** — Auditoría, Swagger, pulido final.

## Cómo ejecutar

**Requisito:** Java 21 instalado.

```bash
# Windows
.\mvnw.cmd spring-boot:run

# Linux / Mac
./mvnw spring-boot:run
```

La aplicación queda escuchando en `http://localhost:8080`.

## Endpoints disponibles (Fase 1)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/api/salud` | Estado de la aplicación |
| `GET` | `/api/usuarios` | Lista de usuarios (mock en memoria) |
| `GET` | `/api/usuarios/{id}` | Detalle de un usuario por id |

## Estructura del proyecto

```
src/main/java/com/tabathapm/iam/
├── IamPlaygroundApplication.java     # Punto de entrada
├── controller/                       # Endpoints REST
│   ├── ControladorSalud.java
│   └── ControladorUsuarios.java
└── dto/                              # Objetos de transferencia
    └── UsuarioDTO.java
```

## Autora

**Tabatha Peralta**  
[GitHub](https://github.com/Tabathapm) · [LinkedIn](https://www.linkedin.com/in/tabatha-peralta/)
