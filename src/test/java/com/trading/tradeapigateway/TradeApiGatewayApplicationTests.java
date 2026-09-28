package com.trading.tradeapigateway;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class TradeApiGatewayApplicationTests {

    public static void main(String[] args) {
        String jwtSecret = "mySuperSecretFallbackKeyThatIsLongEnoughToPreventErrors123456!";
        byte[] secretBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(secretBytes, "HmacSHA256");

        ReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder
                .withSecretKey(key)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        // Token generated earlier by auth-service
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciIsInJvbGVzIjpbIlVTRVIiXSwiaWF0IjoxNzkwNTc0MjU4LCJleHAiOjE3OTA1NzQzMTh9.5jZa-8z2yfQq7xGbFUjm70GDQE0TqKVkDXwVI8mFy0M";

        try {
            Jwt jwt = decoder.decode(token).block();
            System.out.println("Successfully decoded JWT: " + jwt.getClaims());
        } catch (Exception e) {
            System.out.println("Error decoding JWT: " + e.getMessage());
            e.printStackTrace();
        }
    }

}
