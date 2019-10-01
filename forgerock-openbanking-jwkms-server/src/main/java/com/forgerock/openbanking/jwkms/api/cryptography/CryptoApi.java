/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.api.cryptography;

import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.core.model.ValidJwtResponse;
import com.forgerock.openbanking.jwt.model.CreateDetachedJwtResponse;
import com.forgerock.openbanking.jwt.model.ValidDetachedJwtResponse;
import com.forgerock.openbanking.ssl.model.csr.CSRGenerationResponse;
import com.nimbusds.jose.jwk.KeyUse;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

/**
 * Sign/validate JWS and encrypt/decrypt JWE service
 */
@Api(
        tags = "Cryptography",
        description = "Cryptography APIs to manipulate JWTs"
)
@RestController
@RequestMapping("/api/crypto")
public interface CryptoApi {

    /**
     * Sign a set of claims on behalf of an internal application
     *
     * @param claimsSetJsonSerialised claim set in json format
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return A JWS
     */
    @ApiOperation(
            value = "Sign claims",
            notes = "Sign a set of claims",
            response = String.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "JWS with your claims on it", response = String.class),

    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/signClaims",
            method = RequestMethod.POST)
    ResponseEntity<String> signClaims(
            @RequestHeader(value = "issuerId", required = false) String issuerId,
            @RequestBody String claimsSetJsonSerialised,
            Principal principal);

    /**
     * Sign a set of claims on behalf of an internal application
     *
     * @param claimsSetJsonSerialised claim set in json format
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return A JWS
     */
    @ApiOperation(
            value = "Sign claims",
            notes = "Sign a set of claims",
            response = String.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "JWS with your claims on it", response = String.class),

    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/signPayloadToDetachedJwt",
            method = RequestMethod.POST)
    ResponseEntity<CreateDetachedJwtResponse> signPayloadToDetachedJwt(
            @RequestHeader(value = "issuerId", required = false) String issuerId,
            @RequestHeader(value = "signingRequest", required = false) String signingRequestSerialised,
            @RequestBody String claimsSetJsonSerialised,
            Principal principal);

    /**
     * Sign and encrypt set of claims on behalf of an internal application for an unreferenced application
     *
     * @param jwkUri jwk uri of the unreferenced application
     * @param claimsSetJsonSerialised claim set in json format
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return A JWE
     */
    @ApiOperation(
            value = "Sign and encrypt claims for an external app",
            notes = "Sign and encrypt set of claims. As encrypted required the keys of the audience app, its jwk_uri is required.",
            response = String.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "JWE(JWS) with your claims on it", response = String.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/signAndEncryptClaims",
            method = RequestMethod.POST)
    ResponseEntity<String> signAndEncryptJwt(
            @RequestHeader(value = "issuerId", required = false) String issuerId,
            @RequestHeader(value = "jwkUri") String jwkUri,
            @RequestBody String claimsSetJsonSerialised,
            Principal principal);

    /**
     * Sign and encrypt set of claims on behalf of an internal application for another referenced application
     *
     * @param obAppId the application ID for which the JWE will be encrypted
     * @param claimsSetJsonSerialised claim set in json format
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return A JWE
     */
    @ApiOperation(
            value = "Sign and encrypt claims for another registered app in the jwkms",
            notes = "Sign and encrypt set of claims. Encryption required the keys of the audience app and " +
                    "as its also one registered in the jwkms, giving just its issuer ID is enough.",
            response = String.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "JWE(JWS) with your claims on it", response = String.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/signAndEncryptJwtForOBApp",
            method = RequestMethod.POST)
    ResponseEntity<String> signAndEncryptJwtForOBApp(
            @RequestHeader(value = "issuerId", required = false) String issuerId,
            @RequestHeader(value = "obAppId") String obAppId,
            @RequestHeader(value = "includeKey", defaultValue = "false", required = false) boolean includeKey,
            @RequestBody String claimsSetJsonSerialised,
            Principal principal);

    /**
     * Decrypt a JWE(JWS)
     *
     * @param jweSerialized the JWE(JWS) serialized
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return the JWS content into the JWE
     */
    @ApiOperation(
            value = "Decrypt a JWE(JWS)",
            notes = "Decrypt a JWE using our keys",
            response = String.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "JWS that was inside the JWE", response = String.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/decryptJwe",
            method = RequestMethod.POST)
    ResponseEntity<String> decryptJwe(
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestBody String jweSerialized,
            Principal principal);

    /**
     * Validate JWS
     *
     * @param expectedIssuerId the expected issuer for this JWS
     * @param jwsSerialized the JWS serialized that need to be validated
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a validation JWT answer.
     */
    @ApiOperation(
            value = "Validate a JWS",
            notes = "Validate a JWS using your keys",
            response = ValidJwtResponse.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Give the response if the JWS is valid or not", response = ValidJwtResponse.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/validateJws",
            method = RequestMethod.POST)
    ResponseEntity<ValidJwtResponse> validateJws(
            @RequestHeader(value = "expectedIssuerId") String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestBody String jwsSerialized,
            Principal principal);

    /**
     * Validate JWS
     *
     * @param expectedIssuerId the expected issuer for this JWS
     * @param jwsSerialized the JWS serialized that need to be validated
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a validation JWT answer.
     */
    @ApiOperation(
            value = "Validate a JWS",
            notes = "Validate a JWS using your keys",
            response = ValidJwtResponse.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Give the response if the JWS is valid or not", response = ValidJwtResponse.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/validateJwsWithJWK",
            method = RequestMethod.POST)
    ResponseEntity<ValidJwtResponse> validateJwsWithJWK(
            @RequestHeader(value = "expectedIssuerId") String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestHeader(value = "jwk", required = false) String jwk,
            @RequestBody String jwsSerialized,
            Principal principal);


    /**
     * Validate JWS
     *
     * @param expectedIssuerId the expected issuer for this JWS
     * @param jwksUri the issuer jwks uri
     * @param jwsSerialized the JWS serialized that need to be validated
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a validation JWT answer.
     */
    @ApiOperation(
            value = "Validate a JWS",
            notes = "Validate a JWS using your keys",
            response = ValidJwtResponse.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Give the response if the JWS is valid or not", response = ValidJwtResponse.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/validateJwsWithJwkUri",
            method = RequestMethod.POST)
    ResponseEntity<ValidJwtResponse> validateJws(
            @RequestHeader(value = "expectedIssuerId", required = false) String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestHeader(value = "jwksUri") String jwksUri,
            @RequestBody String jwsSerialized,
            Principal principal);


    /**
     * Validate JWS
     *
     * @param expectedIssuerId the expected issuer for this JWS
     * @param jwksUri the issuer jwks uri
     * @param jwsDetachedSignature the JWS detached signature
     * @param bodySerialised the JWT payload
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a validation JWT answer.
     */
    @ApiOperation(
            value = "Validate a JWS",
            notes = "Validate a JWS using your keys",
            response = ValidDetachedJwtResponse.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Give the response if the JWS is valid or not", response = ValidJwtResponse.class),
    })
    @RequestMapping(value = "/validateDetachedJWSWithJwkUri",
            method = RequestMethod.POST)
    ResponseEntity<ValidDetachedJwtResponse> validateDetachedJWSWithJwkUri(
            @RequestHeader(value = "expectedIssuerId", required = false) String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestHeader(value = "jwksUri") String jwksUri,
            @RequestHeader(value = "x-jws-signature") String jwsDetachedSignature,
            @RequestBody String bodySerialised,
            Principal principal);

    /**
     * Validate JWS
     *
     * @param expectedIssuerId the expected issuer for this JWS
     * @param jwsDetachedSignature the JWS detached signature
     * @param bodySerialised the JWT payload
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a validation JWT answer.
     */
    @ApiOperation(
            value = "Validate a JWS",
            notes = "Validate a JWS using your keys",
            response = ValidJwtResponse.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Give the response if the JWS is valid or not", response = ValidJwtResponse.class),
    })
    @RequestMapping(value = "/validateDetachedJWS",
            method = RequestMethod.POST)
    ResponseEntity<ValidJwtResponse> validateDetachedJWS(
            @RequestHeader(value = "expectedIssuerId", required = false) String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestHeader(value = "x-jws-signature") String jwsDetachedSignature,
            @RequestBody String bodySerialised,
            Principal principal);

    /**
     * Validate JWS
     *
     * @param expectedIssuerId the expected issuer for this JWS
     * @param jwsDetachedSignature the JWS detached signature
     * @param bodySerialised the JWT payload
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a validation JWT answer.
     */
    @ApiOperation(
            value = "Validate a JWS",
            notes = "Validate a JWS using your keys",
            response = ValidJwtResponse.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Give the response if the JWS is valid or not", response = ValidJwtResponse.class),
    })
    @RequestMapping(value = "/validateDetachedJWSWithJWK",
            method = RequestMethod.POST)
    ResponseEntity<ValidJwtResponse> validateDetachedJWSWithJWK(
            @RequestHeader(value = "expectedIssuerId", required = false) String expectedIssuerId,
            @RequestHeader(value = "expectedAudienceId", required = false) String expectedAudienceId,
            @RequestHeader(value = "x-jws-signature") String jwsDetachedSignature,
            @RequestHeader(value = "jwk", required = false) String jwk,
            @RequestBody String bodySerialised,
            Principal principal);




    /**
     * Generate a certificate signing request
     *
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a HTTP 200.
     */
    @ApiOperation(
            value = "Generate a CSR",
            notes = "Generate a Certificate Signing Request",
            response = CSRGenerationResponse.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Give the response if the JWS is valid or not", response = CSRGenerationResponse.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/generateCSR",
            method = RequestMethod.POST)
    ResponseEntity<CSRGenerationResponse> generateCSR(
            @RequestParam(value = "keyUse") KeyUse keyUse,
            @RequestParam(value = "certificateConfiguration") CertificateConfiguration certificateConfiguration,

            Principal principal);

    /**
     * Import a certificate signing request response
     *
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a HTTP 200.
     */
    @ApiOperation(
            value = "Import a CSR response",
            notes = "Import a CSR response, from a CSR you already generated with the jwkms",
            response = Void.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "An empty response if you key has been imported"),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/importCSRResponse",
            method = RequestMethod.POST)
    ResponseEntity importCSRResponse(
            @RequestHeader(value = "kid") String kid,
            @RequestHeader(value = "keyUse") KeyUse keyUse,
            @RequestHeader(value = "alias") String alias,
            @RequestBody String pem,
            Principal principal);

    /**
     * Force the rotationScheduler of the keys
     *
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a HTTP 200.
     */
    @ApiOperation(
            value = "Rotate signing and encryption keys",
            notes = "Rotate all your signing and encryption keys. Rotation means your current valid keys would be valid for a reasonable period of time",
            response = Application.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "A sum-up of your current application state", response = Application.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/rotateSigningAndEncryptionKeys",
            method = RequestMethod.POST)
    ResponseEntity<Application> rotateSigningAndEncryptionKeys(
            Principal principal);

    /**
     * Reset all keys. Useful in case of key compromise.
     *
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a HTTP 200.
     */
    @ApiOperation(
            value = "Reset signing and encryption keys",
            notes = "Reset all your signing and encryption keys. Reset means all your current valid keys would be invalidated now.",
            response = Application.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "A sum-up of your current application state", response = Application.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/resetSigningAndEncryptionKeys",
            method = RequestMethod.POST)
    ResponseEntity<Application> resetSigningAndEncryptionKeys(
            Principal principal);

    /**
     * Force the rotationScheduler of the keys
     *
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a HTTP 200.
     */
    @ApiOperation(
            value = "Rotate your transport keys",
            notes = "Rotate all your transport keys.",
            response = Application.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "A sum-up of your current application state", response = Application.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/rotateTransportKeys",
            method = RequestMethod.POST)
    ResponseEntity<Application> rotateTransportKeys(
            Principal principal);

    /**
     * Reset all keys. Useful in case of key compromise.
     *
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a HTTP 200.
     */
    @ApiOperation(
            value = "Reset your transport keys",
            notes = "Reset all your transport keys.",
            response = Application.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "A sum-up of your current application state", response = Application.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/resetTransportKeys",
            method = RequestMethod.POST)
    ResponseEntity<Application> resetTransportKeys(
            Principal principal);

    /**
     * Read application
     *
     * @param principal the internal application ID, populated by the MTLS security layer
     * @return a HTTP 200.
     */
    @ApiOperation(
            value = "Read your application",
            notes = "Read your current application state",
            response = Application.class)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "A sum-up of your current application state", response = Application.class),
    })
    @PreAuthorize("hasRole('ROLE_JWKMS_APP')")
    @RequestMapping(value = "/application",
            method = RequestMethod.GET)
    ResponseEntity<Application> readApplication(
            Principal principal);
}
