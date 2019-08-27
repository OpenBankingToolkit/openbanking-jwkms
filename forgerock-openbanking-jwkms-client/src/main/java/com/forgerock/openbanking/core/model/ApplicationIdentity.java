/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.core.model;

import com.forgerock.openbanking.auth.model.OBRIRole;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ApplicationIdentity {

    private String id;
    private List<OBRIRole> roles = new ArrayList<>();
    private DirectorySrc directorySrc;

    public ApplicationIdentity() {}

    public ApplicationIdentity(String id, List<OBRIRole> roles) {
       this(id, roles, DirectorySrc.FORGEROCK);
    }

    public ApplicationIdentity(String id, List<OBRIRole> roles, DirectorySrc directorySrc) {
        this.id = id;
        this.roles = roles;
        this.directorySrc = directorySrc;
    }

    public ApplicationIdentity(String id, OBRIRole role, DirectorySrc directorySrc) {
        this(id, Arrays.asList(role), DirectorySrc.FORGEROCK);
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<OBRIRole> getRoles() {
        return roles;
    }

    public void addRole(OBRIRole role) {
        this.roles.add(role);
    }
    public void setRoles(List<OBRIRole> roles) {
        this.roles = roles;
    }

    public DirectorySrc getDirectorySrc() {
        return directorySrc;
    }

    public void setDirectorySrc(DirectorySrc directorySrc) {
        this.directorySrc = directorySrc;
    }

    public enum DirectorySrc {
        FORGEROCK, OPEN_BANKING, EXTERNAL_EIDAS
    }

    @Override
    public String toString() {
        return "ApplicationIdentity{" +
                "id='" + id + '\'' +
                ", roles=" + roles +
                ", directorySrc=" + directorySrc +
                '}';
    }
}
