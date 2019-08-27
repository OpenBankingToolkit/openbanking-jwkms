/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms;

import brave.Tracer;
import com.forgerock.openbanking.core.rest.ErrorHandler;
import com.forgerock.openbanking.core.services.security.FormValueSanitisationFilter;
import com.forgerock.openbanking.core.services.security.JsonRequestSanitisiationFilter;
import com.forgerock.openbanking.jwkms.x509.JwkMsMatlsService;
import com.mongodb.MongoClient;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.mongo.MongoLockProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.core.userdetails.UserDetailsService;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import javax.servlet.Filter;


@SpringBootApplication
@EnableSwagger2
@EnableDiscoveryClient
@EnableScheduling
@ComponentScan(basePackages = {"com.forgerock"})
public class ForgerockOpenbankingJwkMSApplication  {

    private JwkMsMatlsService jwkMsMatlsService;

    @Autowired
    public ForgerockOpenbankingJwkMSApplication(JwkMsMatlsService jwkMsMatlsService){
        this.jwkMsMatlsService = jwkMsMatlsService;
    }

    public static void main(String[] args) throws Exception {
        new SpringApplication(ForgerockOpenbankingJwkMSApplication.class).run(args);
    }

    @Bean
    @Primary
    public UserDetailsService userDetailsService() {
        return this.jwkMsMatlsService;
    }


    @Bean
    public LockProvider lockProvider(MongoClient mongo) {
        return new MongoLockProvider(mongo, "lockKeyRotation");
    }

    @Bean
    public Filter jsonSanitisationFilter(ErrorHandler errorHandler, Tracer tracer) {
        return new JsonRequestSanitisiationFilter(errorHandler, tracer);
    }

    @Bean
    public Filter formSanitisationFilter(ErrorHandler errorHandler, Tracer tracer) {
        return new FormValueSanitisationFilter(errorHandler, tracer);
    }
}
