package org.acme;

import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.Base64;
import java.util.Set;

@Provider
@Priority(Priorities.AUTHORIZATION)
@ApplicationScoped
public class SecurityFilter implements ContainerRequestFilter {

    @ConfigProperty(name = "basic.auth.user")
    String user;
    @ConfigProperty(name = "basic.auth.password")
    String password;
    @Inject
    JWTParser jwtParser;

    private static final Set<String> EXCLUDED_PATHS = Set.of("", "");

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String path = requestContext.getUriInfo().getPath();

        if (isExcludedPath(path)) {
            return;
        }

        String authHeader = requestContext.getHeaderString("Authorization");

        if (authHeader == null || authHeader.isEmpty()) {
            //log.warn("No hay Header de Authorization.");
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            return;
        }

        if (authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring("Bearer".length()).trim();
            try {
                jwtParser.parse(token); // Valida el token
                //log.info("Token validado correctamente");
            } catch (ParseException e) {
                //log.warn("Token inválido: " + e.getMessage());
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
        } else if (authHeader.startsWith("Basic ")) {
            String base64Credentials = authHeader.substring("Basic".length()).trim();
            String credentials = new String(Base64.getDecoder().decode(base64Credentials));
            String[] values = credentials.split(":", 2);
            if (values.length != 2 || !isValidUser(values[0], values[1])) {
                //log.warn("Credenciales Basic inválidas");
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
        } else {
            //log.warn("Tipo de autenticación no soportado");
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    private boolean isExcludedPath(String path) {
        return EXCLUDED_PATHS.contains(path);
    }

    private boolean isValidUser(String username, String password) {
        return this.user.equals(username) && this.password.equals(password);
    }
}
