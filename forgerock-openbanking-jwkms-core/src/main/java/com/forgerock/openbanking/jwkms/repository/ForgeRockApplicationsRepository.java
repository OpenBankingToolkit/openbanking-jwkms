/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms.repository;


import com.forgerock.openbanking.core.model.ForgeRockApplication;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * Store the application into a mongoDB (but not the private key, just the public JWK)
 */
public interface ForgeRockApplicationsRepository extends MongoRepository<ForgeRockApplication, String> {
    List<ForgeRockApplication> findByApplicationId(@Param("applicationId") String applicationId);

}
