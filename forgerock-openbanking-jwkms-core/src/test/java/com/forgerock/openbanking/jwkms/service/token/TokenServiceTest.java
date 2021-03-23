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

package com.forgerock.openbanking.jwkms.service.token;

import com.forgerock.openbanking.constants.OpenBankingConstants;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import com.nimbusds.jose.Header;
import com.nimbusds.jwt.JWT;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class TokenServiceTest {

    @Test
    public void validateIssuer_shouldReturnFalseWhenIssuerIsInvalid() throws InvalidTokenException {
        // Given
        TokenService tokenService  = new TokenService();
        JWT mockJwt = mock(JWT.class);
        Header header = mock(Header.class);
        when(header.getCustomParam(OpenBankingConstants.OBJwtHeaderClaims.OB_ISS)).thenReturn("invalidIssuer");
        when(mockJwt.getHeader()).thenReturn(header);

        // when
        boolean isValid = tokenService.validateIssuer(mockJwt, "validIssuer",
                (jwt) -> (String) jwt.getHeader().getCustomParam(OpenBankingConstants.OBJwtHeaderClaims.OB_ISS));

        // Then
        assertThat(isValid).isFalse();
    }

    @Test
    public void validateIssuer_shouldReturnTrueWhenIssuerIsValid() throws InvalidTokenException {
        // Given
        String validIssuer = "validIssuer";
        TokenService tokenService  = new TokenService();
        JWT mockJwt = mock(JWT.class);
        Header header = mock(Header.class);
        when(header.getCustomParam(OpenBankingConstants.OBJwtHeaderClaims.OB_ISS)).thenReturn(validIssuer);
        when(mockJwt.getHeader()).thenReturn(header);

        // when
        boolean isValid = tokenService.validateIssuer(mockJwt, validIssuer,
                (jwt) -> (String) jwt.getHeader().getCustomParam(OpenBankingConstants.OBJwtHeaderClaims.OB_ISS));

        // Then
        assertThat(isValid).isTrue();
    }
}