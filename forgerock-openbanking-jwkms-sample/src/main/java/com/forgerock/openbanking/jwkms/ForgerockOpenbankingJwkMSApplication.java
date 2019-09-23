/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.jwkms;

import com.forgerock.cert.utils.CertificateConfiguration;
import com.forgerock.openbanking.authentication.configurers.MultiAuthenticationCollectorConfigurer;
import com.forgerock.openbanking.authentication.configurers.collectors.StaticUserCollector;
import com.forgerock.openbanking.core.model.Application;
import com.forgerock.openbanking.jwkms.api.application.ApplicationApiController;
import com.forgerock.openbanking.jwkms.config.SelfJwkmsServiceConfiguration;
import com.forgerock.openbanking.jwkms.repository.ApplicationsRepository;
import com.forgerock.openbanking.jwkms.repository.ForgeRockApplicationsRepository;
import com.forgerock.openbanking.jwkms.service.JwkmsServiceConfiguration;
import com.forgerock.openbanking.model.OBRIRole;
import com.mongodb.MongoClient;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.mongo.MongoLockProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.client.RestTemplate;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
@EnableSwagger2
@EnableScheduling
@ComponentScan(basePackages = {"com.forgerock"})
public class ForgerockOpenbankingJwkMSApplication  {


    public static void main(String[] args) throws Exception {
        new SpringApplication(ForgerockOpenbankingJwkMSApplication.class).run(args);
    }

    @Configuration
    static class CookieWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        @Autowired
        private ApplicationApiController applicationApiController;
        @Autowired
        private ApplicationsRepository applicationsRepository;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http

                    .csrf().disable() // We don't need CSRF for JWT based authentication
                    .authorizeRequests()
                    .anyRequest()
                    .permitAll()//.authenticated()
                    .and()
                    .authenticationProvider(new CustomAuthProvider())
                    .apply(new MultiAuthenticationCollectorConfigurer<HttpSecurity>()
                            .collector(StaticUserCollector.builder()
                                    .usernameCollector( () -> {
                                        Optional<Application> isApp = applicationsRepository.findById("anonymous");
                                        if (!isApp.isPresent()) {
                                            Application applicationRequest = new Application();
                                            CertificateConfiguration certificateConfiguration = new CertificateConfiguration();
                                            certificateConfiguration.setCn("anonymous");
                                            applicationRequest.setCertificateConfiguration(certificateConfiguration);

                                            Application application = applicationApiController.createApplication(applicationRequest);
                                            application.setIssuerId("anonymous");
                                            applicationsRepository.save(application);
                                        }
                                        return "anonymous";
                                    })
                                    .grantedAuthorities(Stream.of(
                                            OBRIRole.ROLE_FORGEROCK_EXTERNAL_APP,
                                            OBRIRole.ROLE_JWKMS_APP
                                    ).collect(Collectors.toSet()))
                                    .build())
                    )
            ;
        }
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean(name="forExternal")
    public RestTemplate restTemplateForExternal() {
        return new RestTemplate();
    }

    @Bean(name="forExternalForgeRockApplication")
    public RestTemplate restTemplateForExternalForgeRockApplication() {
        return new RestTemplate();
    }

    @Bean
    public JwkmsServiceConfiguration jwkmsServiceConfiguration() {
        return new SelfJwkmsServiceConfiguration();
    }

    public static class CustomAuthProvider implements AuthenticationProvider {

        @Autowired
        private ForgeRockApplicationsRepository forgeRockApplicationsRepository;

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            //You can load more GrantedAuthority based on the user subject, like loading the TPP details from the software ID
            return authentication;
        }

        @Override
        public boolean supports(Class<?> aClass) {
            return true;
        }
    }

    @Bean
    public LockProvider lockProvider(MongoClient mongo) {
        return new MongoLockProvider(mongo, "lockKeyRotation");
    }
}
