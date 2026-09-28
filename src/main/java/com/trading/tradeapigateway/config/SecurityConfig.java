package com.trading.tradeapigateway.config;


import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {



    @Value("${jwt.secret}")
    private String jwtSecret;


    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        // Public endpoint
                        .pathMatchers("/actuator/health","/auth/register")
                        .permitAll()
                        // Everything else requires authentication
                        .anyExchange()
                        .authenticated()
                )

                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(jwt ->
                                jwt.jwtDecoder(jwtDecoder())
                        )
                )


                .build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {


        byte[] secretBytes =
                jwtSecret.getBytes(StandardCharsets.UTF_8);

        SecretKey key = new SecretKeySpec(
                secretBytes,
                "HmacSHA256"
        );

        return NimbusReactiveJwtDecoder
                .withSecretKey(key)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }


    @PostConstruct
    public void debugJwtSecret() {

        System.out.println(
                "Gateway JWT secret length = " + jwtSecret.length()
        );

        System.out.println(
                "Gateway JWT secret hash = " + jwtSecret.hashCode()
        );
    }
}

