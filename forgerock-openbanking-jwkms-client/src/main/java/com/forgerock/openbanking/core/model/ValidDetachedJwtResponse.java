/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Slf4j
public class ValidDetachedJwtResponse {

    private static ValidDetachedJwtResponse VALID_JWT = new ValidDetachedJwtResponse(true, "");

    public boolean isValid;
    public String message;
    public String reconstructJWS;

    @JsonIgnore
    public static ValidDetachedJwtResponse valid() {
        return VALID_JWT;
    }

    @JsonIgnore
    public static ValidDetachedJwtResponse invalid(String message) {
        return new ValidDetachedJwtResponse(false, message);
    }

    public ValidDetachedJwtResponse(boolean isValid, String message) {
        this.isValid = isValid;
        this.message = message;
    }

    @JsonIgnore
    public static Object valid(SignedJWT jws) {

        ValidDetachedJwtResponse.ValidDetachedJwtResponseBuilder builder = ValidDetachedJwtResponse.builder()
                .isValid(true)
                .reconstructJWS(jws.serialize())
                ;

        return builder.build();
    }

    @JsonIgnore
    public boolean getValid() {
        return isValid;
    }
}
