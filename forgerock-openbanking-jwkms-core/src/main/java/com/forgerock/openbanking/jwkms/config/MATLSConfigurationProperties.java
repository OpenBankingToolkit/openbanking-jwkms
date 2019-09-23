/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@ConfigurationProperties(prefix = "matls")
public class MATLSConfigurationProperties {

    private String forgerockInternalCAAlias;
    private String forgerockExternalCAAlias;
    private List<String> forgerockGatewaySubIds;
    private List<String> monitoringAppsIds;

    public String getForgerockInternalCAAlias() {
        return forgerockInternalCAAlias;
    }

    public void setForgerockInternalCAAlias(String forgerockInternalCAAlias) {
        this.forgerockInternalCAAlias = forgerockInternalCAAlias;
    }

    public String getForgerockExternalCAAlias() {
        return forgerockExternalCAAlias;
    }

    public void setForgerockExternalCAAlias(String forgerockExternalCAAlias) {
        this.forgerockExternalCAAlias = forgerockExternalCAAlias;
    }

    public List<String> getForgerockGatewaySubIds() {
        return forgerockGatewaySubIds;
    }

    public void setForgerockGatewaySubIds(List<String> forgerockGatewaySubIds) {
        this.forgerockGatewaySubIds = forgerockGatewaySubIds;
    }

    public List<String> getMonitoringAppsIds() {
        return monitoringAppsIds;
    }

    public void setMonitoringAppsIds(List<String> monitoringAppsIds) {
        this.monitoringAppsIds = monitoringAppsIds;
    }
}
