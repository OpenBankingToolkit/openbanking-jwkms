/**
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
package com.forgerock.openbanking.core.model;

import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;

import java.text.ParseException;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Slf4j
public class ValidJwtResponse {

    private static ValidJwtResponse VALID_JWT = new ValidJwtResponse(true, "");

    public boolean isValid;
    public String message;
    public JSONObject jwtHeader;
    public Object jwtPayload;
    public String originalJWS;

    public static ValidJwtResponse valid() {
        return VALID_JWT;
    }

    public static ValidJwtResponse invalid(String message) {
        return new ValidJwtResponse(false, message);
    }

    private ValidJwtResponse(boolean isValid, String message) {
        this.isValid = isValid;
        this.message = message;
    }

    public static Object valid(SignedJWT jws) {

        ValidJwtResponseBuilder builder = ValidJwtResponse.builder()
                .isValid(true)
                .jwtHeader(jws.getHeader().toJSONObject())
                ;

        try {
            builder.jwtPayload(jws.getJWTClaimsSet().toJSONObject());
        } catch (ParseException e) {
            log.warn("Can't parse the payload of the JWT into a JSON, return raw payload instead", e);
            builder.jwtPayload(jws.getPayload().toString());
        }

        return builder.build();
    }
}
