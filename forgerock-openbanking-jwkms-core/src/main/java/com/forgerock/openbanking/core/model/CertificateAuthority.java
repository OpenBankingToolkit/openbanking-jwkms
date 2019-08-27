/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.model;

import java.util.List;

/**
 * Representation of the application
 */
public class CertificateAuthority extends Application{

    private List<String> kidSignedUsingThisCA;

    public List<String> getKidSignedUsingThisCA() {
        return kidSignedUsingThisCA;
    }

    public void setKidSignedUsingThisCA(List<String> kidSignedUsingThisCA) {
        this.kidSignedUsingThisCA = kidSignedUsingThisCA;
    }
}
