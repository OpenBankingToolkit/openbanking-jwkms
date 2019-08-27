/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.model;

import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;

import java.text.ParseException;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Slf4j
public class ValidJwtResponse {

    private static ValidJwtResponse VALID_JWT = new ValidJwtResponse(true, "");

    public boolean isValid;
    public String message;
    public JSONObject jwtHeader;
    public Object jwtPayload;
    public String originalJWS;

    public static ValidJwtResponse valid() {
        return VALID_JWT;
    }

    public static ValidJwtResponse invalid(String message) {
        return new ValidJwtResponse(false, message);
    }

    private ValidJwtResponse(boolean isValid, String message) {
        this.isValid = isValid;
        this.message = message;
    }

    public static Object valid(SignedJWT jws) {

        ValidJwtResponseBuilder builder = ValidJwtResponse.builder()
                .isValid(true)
                .jwtHeader(jws.getHeader().toJSONObject())
                ;

        try {
            builder.jwtPayload(jws.getJWTClaimsSet().toJSONObject());
        } catch (ParseException e) {
            log.warn("Can't parse the payload of the JWT into a JSON, return raw payload instead", e);
            builder.jwtPayload(jws.getPayload().toString());
        }

        return builder.build();
    }
}
