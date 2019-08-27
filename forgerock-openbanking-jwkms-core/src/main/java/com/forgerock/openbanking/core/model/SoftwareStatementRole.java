/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.model;


import com.forgerock.cert.psd2.Psd2Role;

import java.util.Optional;

public enum SoftwareStatementRole {
    // Account Information Service Provider
    AISP,
    // Payment Initiation Services Provider
    PISP,
    // Account Servicing Payment Service Provider
    ASPSP,
    // Card Based Payment Instrument Issuer
    CBPII,
    // A Role used to protect the /data endpoint
    DATA;

    public Optional<Psd2Role> getPsd2Role(){
        switch (this) {
            // Account Information Service Provider
            case AISP:
                return Optional.of(Psd2Role.PSP_AI);
            case PISP:
                return Optional.of(Psd2Role.PSP_PI);
            case ASPSP:
                return Optional.of(Psd2Role.PSP_AS);
            case CBPII:
                return Optional.of(Psd2Role.PSP_IC);
            case DATA:
                return Optional.empty();
            default:
                throw new IllegalArgumentException(this.toString() + " is an unrecognised role");
        }
    }

    public static Optional<SoftwareStatementRole> getSSRole(Psd2Role psd2Role){
        SoftwareStatementRole role = null;
        switch(psd2Role){
            case PSP_AI:
                role = SoftwareStatementRole.AISP;
                break;
            case PSP_PI:
                role = SoftwareStatementRole.PISP;
                break;
            case PSP_AS:
                role = SoftwareStatementRole.ASPSP;
                break;
            case PSP_IC:
                role = SoftwareStatementRole.CBPII;
                break;
        }
        return Optional.ofNullable(role);
    }
}