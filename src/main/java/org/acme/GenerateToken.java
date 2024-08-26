package org.acme;

import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.jwt.Claims;

import java.util.Arrays;
import java.util.HashSet;

@ApplicationScoped
public class GenerateToken {

    public String generate(String email, String rol){
        String token = Jwt
                .upn(email)
                .groups(new HashSet<>(Arrays.asList(rol)))
                .claim(Claims.birthdate.name(), "2001-07-13")
                .sign();
        return token;
    }

}
