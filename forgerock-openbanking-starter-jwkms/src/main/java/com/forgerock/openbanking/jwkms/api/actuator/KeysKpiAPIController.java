/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.api.actuator;

import com.forgerock.openbanking.core.model.jwkms.Application;
import com.forgerock.openbanking.core.model.jwkms.JwkMsKey;
import com.forgerock.openbanking.core.model.metrics.kpi.KeysAlgorithmKPI;
import com.forgerock.openbanking.core.model.metrics.kpi.KeysStatusKPI;
import com.forgerock.openbanking.core.model.metrics.kpi.KeysTypeKPI;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/actuator/keys")
public class KeysKpiAPIController {

    @Autowired
    private ApplicationsRepository applicationsRepository;

    @RequestMapping(value = "/type", method = RequestMethod.GET)
    public ResponseEntity<KeysTypeKPI> getKeysTypeKPI(
            @RequestParam(value = "fromDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) DateTime fromDateTime,
            @RequestParam(value = "toDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) DateTime toDateTime
    ) {
        KeysTypeKPI keysTypeKPI = new KeysTypeKPI();
        for (Application application : applicationsRepository.findAll()) {
            keysTypeKPI.increment(KeysTypeKPI.Type.TRANSPORT, application.getTransportKeys().size());
            for (JwkMsKey key:  application.getKeys().values()) {
                if (filterKey(key, fromDateTime, toDateTime)) {
                    if (KeyUse.SIGNATURE.equals(key.getKeyUse())) {
                        keysTypeKPI.increment(KeysTypeKPI.Type.SIGNING);
                    } else if (KeyUse.ENCRYPTION.equals(key.getKeyUse())) {
                        keysTypeKPI.increment(KeysTypeKPI.Type.ENCRYPTION);
                    }
                }
            }
        }
        return ResponseEntity.ok(keysTypeKPI);
    }

    @RequestMapping(value = "/algorithm", method = RequestMethod.GET)
    public ResponseEntity<KeysAlgorithmKPI> getKeysAlgorithmKPI(
            @RequestParam(value = "fromDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) DateTime fromDateTime,
            @RequestParam(value = "toDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) DateTime toDateTime
    ) {
        KeysAlgorithmKPI keysAlgorithmKPI = new KeysAlgorithmKPI();
        for (Application application : applicationsRepository.findAll()) {
            for (JwkMsKey key:  application.getKeys().values()) {
                if (filterKey(key, fromDateTime, toDateTime)) {
                    keysAlgorithmKPI.increment(KeyType.forAlgorithm(key.getAlgorithm()));
                }
            }
            for (JwkMsKey key:  application.getTransportKeys().values()) {
                if (filterKey(key, fromDateTime, toDateTime)) {
                    keysAlgorithmKPI.increment(KeyType.forAlgorithm(key.getAlgorithm()));
                }
            }
        }
        return ResponseEntity.ok(keysAlgorithmKPI);
    }

    @RequestMapping(value = "/status", method = RequestMethod.GET)
    public ResponseEntity<KeysStatusKPI> getKeysStatusKPI(
            @RequestParam(value = "fromDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) DateTime fromDateTime,
            @RequestParam(value = "toDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) DateTime toDateTime
    ) {
        KeysStatusKPI keysStatusKPI = new KeysStatusKPI();
        for (Application application : applicationsRepository.findAll()) {
            for (JwkMsKey key:  application.getKeys().values()) {
                if (filterKey(key, fromDateTime, toDateTime)) {
                    if (key.getValidityWindowStop() == null) {
                        keysStatusKPI.increment(KeysStatusKPI.Status.ACTIVE);
                    } else if (key.getValidityWindowStop().isAfterNow()) {
                        keysStatusKPI.increment(KeysStatusKPI.Status.EXPIRED);
                    } else {
                        keysStatusKPI.increment(KeysStatusKPI.Status.REVOKED);
                    }
                }
            }
            for (JwkMsKey key:  application.getTransportKeys().values()) {
                if (filterKey(key, fromDateTime, toDateTime)) {
                    if (key.getValidityWindowStop() == null) {
                        keysStatusKPI.increment(KeysStatusKPI.Status.ACTIVE);
                    } else if (key.getValidityWindowStop().isAfterNow()) {
                        keysStatusKPI.increment(KeysStatusKPI.Status.EXPIRED);
                    } else {
                        keysStatusKPI.increment(KeysStatusKPI.Status.REVOKED);
                    }
                }
            }
        }
        return ResponseEntity.ok(keysStatusKPI);
    }

    private boolean filterKey(JwkMsKey key,  DateTime fromDateTime, DateTime toDateTime) {
        return key.getCreated() != null && fromDateTime.isBefore(key.getCreated()) && toDateTime.isAfter(key.getCreated());
    }
}
