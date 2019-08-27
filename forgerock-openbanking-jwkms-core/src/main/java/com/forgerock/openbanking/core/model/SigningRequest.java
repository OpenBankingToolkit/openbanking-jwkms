/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.model;

import lombok.*;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SigningRequest {

    public static final Set<String> DEFAULT_SUPPORT_CRIT_CLAIMS = Stream.of(
            OBJwtHeaderClaims.B64,
            OBJwtHeaderClaims.OB_ISS,
            OBJwtHeaderClaims.OB_IAT,
            OBJwtHeaderClaims.OB_TAN
    ).collect(Collectors.toSet());

    @Builder.Default private CustomHeaderClaims customHeaderClaims = CustomHeaderClaims.builder().build();

    @Data
    @Builder
    @ToString
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CustomHeaderClaims {
        @Builder.Default private boolean includeB64 = false;
        @Builder.Default private boolean includeOBIat = false;
        @Builder.Default private boolean includeOBIss = false;
        @Builder.Default private String tan = null;
        @Builder.Default private boolean includeCrit = false;
    }
}
