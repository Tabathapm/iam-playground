package com.tabathapm.iam.controller;

import java.time.Instant;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/*
  Controlador de "salud" de la aplicación.
 
  Sirve para que herramientas externas (balanceadores de carga, Kubernetes,
  monitores de uptime, etc.) puedan preguntarle al sistema "estás viva?".
  Por convención de la industria, las APIs exponen este tipo de endpoint
  para chequeos automáticos.
 */
@RestController                              // Esta clase atiende peticiones HTTP y devuelve JSON
@RequestMapping("/api/salud")                // Todos los métodos de la clase cuelgan de /api/salud
public class ControladorSalud {

    /**
      Responde a la petición GET /api/salud.
     
      Devuelve un mapa que Spring serializa automáticamente a JSON.
      Spring usa la librería Jackson para convertirlo automáticamente a JSON
      antes de enviarlo al cliente.
     */
    @GetMapping
    public Map<String, Object> salud() {
        return Map.of(
            "estado",      "ACTIVO",
            "servicio",    "iam-playground",
            "fechaHora",   Instant.now().toString()
        );
    }
}