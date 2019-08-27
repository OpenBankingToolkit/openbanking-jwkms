/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.model;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum OBRIRole implements GrantedAuthority {

    ROLE_ANONYMOUS,
    ROLE_AUTHENTICATED,
    ROLE_JWKMS_APP,
    ROLE_USER,
    ROLE_ADMIN,
    ROLE_TPP,
    ROLE_AISP,
    ROLE_PISP,
    ROLE_CBPII,
    ROLE_DATA,
    ROLE_SOFTWARE_STATEMENT,
    ROLE_ASPSP,
    ROLE_GATEWAY,
    ROLE_MONITORING,
    ROLE_FORGEROCK_INTERNAL_APP,
    ROLE_FORGEROCK_EXTERNAL_APP,
    ROLE_ID_TOKEN,
    ROLE_EIDAS,

    //JWKMS
    ROLE_ABOUT_EXPIRED_TRANSPORT,
    ROLE_EXPIRED_TRANSPORT,

    UNREGISTERED_TPP,
    UNKNOWN_CERTIFICATE
    ;

    public static boolean isTpp(List<OBRIRole> roles) {
        return Collections.disjoint(roles, Stream.of(OBRIRole.ROLE_AISP, OBRIRole.ROLE_PISP, OBRIRole.ROLE_CBPII).collect(Collectors.toSet()));
    }

    public String getAuthority() {
        return this.name();
    }

    public static OBRIRole fromSoftwareStatementType(SoftwareStatementRole role) {
        switch (role) {
            case AISP:
                return ROLE_AISP;
            case PISP:
                return ROLE_PISP;
            case ASPSP:
                return ROLE_ASPSP;
            case CBPII:
                return ROLE_CBPII;
            case DATA:
                return ROLE_DATA;
            default:
                return ROLE_ANONYMOUS;
        }
    }

    public static Optional<SoftwareStatementRole> convertToSoftwareStatementRole(OBRIRole role) {
        switch (role) {
            case ROLE_AISP:
                return Optional.of(SoftwareStatementRole.AISP);
            case ROLE_PISP:
                return Optional.of(SoftwareStatementRole.PISP);
            case ROLE_CBPII:
                return Optional.of(SoftwareStatementRole.CBPII);
            default:
                return Optional.empty();
        }
    }

    public static List<SoftwareStatementRole> convertToSoftwareStatementRoles(List<OBRIRole> roles) {
        return roles.stream()
                .map(c -> convertToSoftwareStatementRole(c))
                .filter(c -> c.isPresent())
                .map(c -> c.get())
                .collect(Collectors.toList());
    }
}
