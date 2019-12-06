/**
 * Copyright 2019 ForgeRock AS.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.forgerock.openbanking.jwkms.api.application;

import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.model.ApplicationIdentity;
import com.forgerock.openbanking.ssl.model.ForgeRockApplicationResponse;
import io.swagger.annotations.Api;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.security.Principal;
import java.util.List;

@Api(
        tags = "Application",
        description = "Each consumer of the jwkms, like a software statement, is view as an application for the jwkms"
)
public interface ApplicationApi {

    /*
        READ APP
     */

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/", method = RequestMethod.GET)
    ResponseEntity<List<Application>> getAllApplication();

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{appId}", method = RequestMethod.GET)
    ResponseEntity<Application> read(@PathVariable String appId, Principal principal);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/forgerock-app/{name}/jwk_uri", method = RequestMethod.GET)
    ResponseEntity<String> getForgeRockJwkUri(@PathVariable(name = "name") String name);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{appId}/transport/jwk_uri", method = RequestMethod.GET)
    ResponseEntity<String> transportKeysJwkUri(@PathVariable String appId, Principal principal);

    /*
        EDIT APP
    */

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/", method = RequestMethod.POST)
    ResponseEntity<Application> create(@RequestBody Application application);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{applicationId}", method = RequestMethod.DELETE)
    ResponseEntity delete(@PathVariable(value = "applicationId") String applicationId, Principal principal);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{appId}/transport/rotate", method = RequestMethod.PUT)
    ResponseEntity<Application> transportKeysRotate(@PathVariable String appId, Principal principal);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{appId}/transport/reset", method = RequestMethod.PUT)
    ResponseEntity<Application> transportKeysReset(@PathVariable String appId, Principal principal);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{appId}/jwk_uri", method = RequestMethod.GET)
    ResponseEntity<String> signingEncryptionKeysJwkUri(@PathVariable String appId, Principal principal);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{appId}/rotate", method = RequestMethod.PUT)
    ResponseEntity<Application> signingEncryptionKeysRotate(@PathVariable String appId, Principal principal);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{appId}/reset", method = RequestMethod.PUT)
    ResponseEntity<Application> signingEncryptionKeysReset(@PathVariable String appId, Principal principal);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{appId}/key/{keyId}", method = RequestMethod.PUT)
    ResponseEntity<String> getKey(
            @PathVariable(name = "appId") String appId,
            @PathVariable(name = "keyId") String keyId,
            Principal principal);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{appId}/key/{keyId}/certificate/public/", method = RequestMethod.PUT)
    ResponseEntity<String> getPublicCertificate(
            @PathVariable(name = "appId") String appId,
            @PathVariable(name = "keyId") String keyId,
            Principal principal);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/{appId}/key/{keyId}/certificate/private/", method = RequestMethod.PUT)
    ResponseEntity<String> getPrivateCertificate(
            @PathVariable(name = "appId") String appId,
            @PathVariable(name = "keyId") String keyId,
            Principal principal);

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    ResponseEntity<ApplicationIdentity> authenticate(@RequestBody String jwkSerialised);

    /*
        CURRENT APP
    */

    @PreAuthorize("hasAnyAuthority('ROLE_FORGEROCK_INTERNAL_APP', 'ROLE_FORGEROCK_EXTERNAL_APP', 'ROLE_JWKMS_APP')")
    @RequestMapping(value = "/current", method = RequestMethod.GET)
    ResponseEntity<ForgeRockApplicationResponse> getCurrentApplication(Principal principal);
}
