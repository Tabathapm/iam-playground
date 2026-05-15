package com.tabathapm.iam.dto;

/**
 * DTO con el token que devolvemos al cliente despues de un login exitoso.
 *
 * Por convencion incluimos:
 *   - token: el JWT
 *   - tipo: "Bearer" (es el estandar OAuth para indicar como usar el token)
 *   - expiraEnSegundos: cuanto tiempo es valido
 */
public record RespuestaToken(
    String token,
    String tipo,
    long expiraEnSegundos
) {
    public static RespuestaToken bearer(String token, long expiraEnSegundos) {
        return new RespuestaToken(token, "Bearer", expiraEnSegundos);
    }
}