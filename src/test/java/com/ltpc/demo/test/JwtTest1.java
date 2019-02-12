package com.ltpc.demo.test;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.AesKey;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 * User: liutong
 * Date: 2019-02-12
 * Time: 16:23
 * Description:
 **/
public class JwtTest1 {

    public static void main(String[] args) {
        String signKey = "jJlkccl17vF0ZDL120heyvpv6bOm0qqu6bOm0qqu0qquserdersqerr45eRw5R4equ0qquserdersqerr45eRw5R4e";
        String decryptionKey = "jJlkccl17vF0ZDLIh0heyvpv6bOm0qqY6bOm0qqY0qy";
        Key SIGN_KEY = new AesKey(signKey.getBytes(StandardCharsets.UTF_8));
        Key DECRYPTION_KEY = new AesKey(decryptionKey.getBytes(StandardCharsets.UTF_8));

        String token = "eyJhbGciOiJIUzUxMiJ9" +
                ".ZXlKNmFYQWlPaUpFUlVZaUxDSmhiR2NpT2lKa2FYSWlMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4wLi5mNkhvbW5GdUhZTGVnMmdOdkNZVG13Lll6eVJkUnhsakpmdFVQYWsydjVXS25YYXZVYzBvc28zZUFiNFRDcHRBNGZoVHQ3ZkVSUFBYVnAzOGxjWWRJVjhDb2pkWkxTdHc1QjAwamxHZTktTVY2SkY5bkdLZGJFUGYwTWNvaWpWQ19sTnhKeVNHNUJvQWxwQ19vXzdhM2VXd3ViczRyWlFiV1MtU0VNVkozYVpQVEs5SllQbDJYZWk0dXIyU2Y5Nk8ybU5kOFRyazFPS05EMmNPU0dqWHk5aGM3MzBMRUkzV21hSE1tQ0JmalNleHJNX19NdVdwX2FEU1htV0xVcUYwZVpWTW5MUy15TTd2TUpybkI2TkRqYkNmSnZLTVlnLVBvWXRfMjZNNTliS2Z3bzZfUk45RC1UQUUtY2RNamJqSnlqZF9neWgtLXh0Y3RMMDI1VnVfT3lWNldSWjB3Z0ZRbVc0Qmc4X3Q2b0tkZXVLNVhiZ3JOU2VuZENYejFYUmZDYmM5aHI4d3cwMlhCanRJRUZJc01uQjBDdnN3aC1LaGpZcHVHeENLM0RhMERjX1ZZSkdtalNEX190V2tBYTM3ZHZ0R1dnR2ZGZXd0a2c0M1c5WUZmcnFyM1F1NFZwamV1Qzl2MWRzUDRZQnhnWlBndnNaWmItZi1meFQ5MHE1V0t6RWJ3bU5QaEhTSEU4Rmd2Y056a0paUG9weWxPMWd4QnVIam5IRWxmMHFSQS5nTEdUdVN0dlhBS0ZqTEEyMG5RVkp3" +
                ".ir2fDyiVgYYJChrXJqs9UvBa_aU15W8VfVC3wbDXE_2Yv6_em-LDmA4r5TAeirQFZT3zg0WdH8tv827ypW_FZw";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                // the JWT must have an expiration time
                .setRequireExpirationTime()
                // but the  expiration time can't be too crazy
                .setMaxFutureValidityInMinutes(4800)
                // allow some leeway in validating time based claims to account for clock skew
                .setAllowedClockSkewInSeconds(30)
                // the JWT must have a subject claim
                .setRequireSubject()
                // whom the JWT needs to have been issued by
                .setExpectedIssuer("http://localhost:8080/uac")
                // to whom the JWT is intended for
                .setExpectedAudience("http://localhost:8085/")
                // verify the signature with the public key
                .setVerificationKey(SIGN_KEY)
                .setDecryptionKey(DECRYPTION_KEY)
                .build();
        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
            System.out.println("JWT validation succeeded! " + jwtClaims);
            Map<String, Object> claims = jwtClaims.getClaimsMap();
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                System.out.println("Key = " + entry.getKey() + ", Value = " + entry.getValue());
            }
        } catch (InvalidJwtException e) {
            e.printStackTrace();
        }
    }
}
