/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.api.mtls;

import com.forgerock.openbanking.auth.model.OBRIRole;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;

@Api(
        tags = "MATLS",
        description = "Testing your MATLS setup"
)
@RestController
@RequestMapping("/mtls")
public class MtlsTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(MtlsTest.class);

    public static class MtlsTestResponse {
        public String message;
        public Collection<? extends GrantedAuthority> authorities = new ArrayList<>();
    }

    @ApiOperation(value = "Test your MATLS setup", response = MtlsTestResponse.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Your identity", response = MtlsTestResponse.class),

    })
    @GetMapping(value = "/test")
    public ResponseEntity<MtlsTestResponse> mtlsTest(Principal principal) {
        LOGGER.debug("Mtls test. Principal {}", principal);

        MtlsTestResponse response = new MtlsTestResponse();
        if (principal == null) {
            LOGGER.debug("The third party is not authenticated, we consider it as an anonymous.");
            response.message = "Hello anonymous! Add your certificate into your web browser or postman to authenticate";
        } else {
            UserDetails currentUser = (UserDetails) ((Authentication) principal).getPrincipal();
            if (currentUser.getAuthorities().contains(OBRIRole.ROLE_EXPIRED_TRANSPORT)) {
                LOGGER.debug("The third party is authenticated, it is {} with authorities {}, but he is using an expired transport certificate.",
                        currentUser.getUsername(), currentUser.getAuthorities());
                response.message = "Hello " + currentUser.getUsername() + ", you are using one of your expired transport certificate. You need to use a valid one";
                response.authorities = currentUser.getAuthorities();
            } else if (currentUser.getAuthorities().contains(OBRIRole.ROLE_ABOUT_EXPIRED_TRANSPORT)) {
                LOGGER.debug("The third party is authenticated, it is {} with authorities {}. Note: he is using a transport certificate that will expire.",
                        currentUser.getUsername(), currentUser.getAuthorities());
                response.message = "Hello " + currentUser.getUsername() + "! Note that you are using a transport certificate that will expire soon. Think of using your new transport certificate.";
                response.authorities = currentUser.getAuthorities();
            } else {
                LOGGER.debug("The third party is authenticated, it is {} with authorities {}.",
                        currentUser.getUsername(), currentUser.getAuthorities());
                response.message = "Hello " + currentUser.getUsername() + "!";
                response.authorities = currentUser.getAuthorities();
            }
        }
        LOGGER.debug("response {}", response);
        return ResponseEntity.ok(response);
    }
}
