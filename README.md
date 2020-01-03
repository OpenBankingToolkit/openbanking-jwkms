[<img src="https://raw.githubusercontent.com/ForgeRock/forgerock-logo-dev/master/Logo-fr-dev.png" align="right" width="220px"/>](https://developer.forgerock.com/)

| |Current Status|
|---|---|
|Build|[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2FOpenBankingToolkit%2Fopenbanking-jwkms%2Fbadge%3Fref%3Dmaster&style=flat)](https://actions-badge.atrox.dev/OpenBankingToolkit/openbanking-jwkms/goto?ref=master)|
|Code coverage|[![codecov](https://codecov.io/gh/OpenBankingToolkit/openbanking-jwkms/branch/master/graph/badge.svg)](https://codecov.io/gh/OpenBankingToolkit/openbanking-jwkms)
|Bintray|[![Bintray](https://img.shields.io/bintray/v/openbanking-toolkit/OpenBankingToolKit/openbanking-jwkms.svg?maxAge=2592000)](https://bintray.com/openbanking-toolkit/OpenBankingToolKit/openbanking-jwkms)|
|License|![license](https://img.shields.io/github/license/ACRA/acra.svg)|

**_This repository is part of the Open Banking Tool kit. If you just landed to that repository looking for our tool kit,_
_we recommend having a first read to_ https://github.com/OpenBankingToolkit/openbanking-toolkit**

ForgeRock OpenBanking Json Web Key Management Service (JWKMS)
========================

The JWKMS provides essential key management functionality that allows integration with other parties using Json Web Tokens (JWTs) as a communication format.

This becomes very handy for OIDC clients for example where there is a need to use JWTs as a request parameter during dynamic registration or using JWTs authentication method.

The JWKMS provides you the following features:

* Creation of transport, signing and encryption keys
* Publication of those keys as public JWK under the standard format JWK_URI
* Key rotation (previous keys still accepted for a certain window of time)
* Revocation of keys (previous keys are not invalid)
* Sign or/and encrypt a payload into a JWTs, using your current keys (manages the all JWTs format for you)
* Validation of JWTs
* Signing and creation of detached signature JWTs (You give it a payload and returns you a detached signature JWT)
* Validation detached signature JWTs
* Download your keys as certificates

The JWKMS is able to manage asymmetric keys of types : EC, RS and PS

The JWKMS can be deploy in two different ways:
* Centralised JWKMS instance
* Embedded into your app


## Centralised JWKMS instance

The JWKMS can be deployed as a micro-service. In that configuration, the JWKMS can be used to manage keys for multiple applications at the same time. This means that your other micro-services can delegate all JWTs manipulation and JWK management to the JWKMS.
 A centralised JWKMS into your environment offers the following advantages:

 * Your other micro-services are smaller in size and require less resources as cryptography is CPU intensive. By delegating the cryptography to the JWKMS micro-service it is possible to allocate resources dynamically and scale is resource intensive function independently of the consuming service. 
 * The JWKMS does cryptography tasks, which needs to use the latest security fixes and optimisations. Having it centralised allows you to update the JWKMS without impacting your other microservices and without having to upgrade each of them.
 * The JWKMS is stateless and can be scaled horizontally. If you need better crypto performances, you can avoid having to scale all your microservices and simply scale up the JWKMS.
 * You can force all of your micro-services to rotate their keys in one place: instead of having to call all your micro-services independently.
 * Changing algorithms to all your microservices is simplified: you can change the default algorithms in the jwkms instance and all your microservices will start to use it.

The JWKMS must be able to identify the client application calling it's services in order that the correct keys belonging to that service may be used. This means that each micro service must authenticate to the JWKMS. This is done using MATLS.


### Include the dependencies

For Apache Maven:

```
<dependency>
    <groupId>com.forgerock.openbanking.jwkms</groupId>
    <artifactId>forgerock-openbanking-jwkms-server</artifactId>
</dependency>
```

For Gradle:

```
compile 'com.forgerock.openbanking.jwkms:forgerock-openbanking-jwkms-server'
```


## Embedded into your app

In smaller environment, you may not want to have a dedicated JWKMS instance but more offer a JWKMS capacity inside each of your microservices directly. By embedding the JWKMS as a Java library your app will be able to manipulate JWTs and manage it's own key out of the box. 

Having it embedded requires more resources for your micro-services. From a security side of things, you will need to do more regular upgrades or individual actions for each of your micro-services.

Read the advantages of a single micro-services to understand the implication of having it embedded instead.

The advantages of having an embedded JWKMS is that it removes a micro-service dependency. Your microservice can be deployed independently without relying on the availability of another one.
It simplified your deployment and your micro-services management.

### Include the dependencies

For Apache Maven:

```
<dependency>
    <groupId>com.forgerock.openbanking.clients</groupId>
    <artifactId>forgerock-openbanking-jwkms-client</artifactId>
</dependency>
```

For Gradle:

```
compile 'com.forgerock.openbanking.clients:forgerock-openbanking-jwkms-client'
```


## When should I choose centralised VS embedded?

* If you are doing a POC, a test, examples, etc, the embedded approach can make a lot of sense.

* If you are building a production environment, where you aim for best performances, scalability, easy maintenance and better security risk management, go for the centralised approach.

* If you don't have many microservices relying on the JWKMS and you can afford spending a bit more resources by scaling each microservices instead of just the JWKMS, go for the embedded approach.

The centralised vs embedded is really a trade off. Centralised is more flexible and more resource efficient but requires more work in your deployment. Embedded is definitively easier to put in place but may restrict you in your scalability and resource management in your cluster.


# JWKMS acting as CA

The JWKMS manages keys and offers to export them as certificates. If you are not interested by the certificate format, you can skip this section. However if you are interested in how to make the JWKMS sign your keys using a specific CA certificate then read on!

The JKWMS uses self-signed certificate CA by default and will generate keys using this CA certificate:
It creates a CSR and uses the self signed certificate for getting a new key issue by this CA certificate.

Where your keys are exposed to external parties you may want to use a dedicated Certificate Authority. This can be achieved by defining the interface `JwkStoreService` and annotating it as the primary bean. This will delegate the key creation to your service and you will be able to customise the key creation, by calling your CA dedicated API for example.

# Building
To build the source locally you'll need the following tools installed:
- Docker
- Maven
- Java 11

```
mvn install
```

# Testing
Given you have the tools to build the source the same toolset is required for testing.
```
mvn verify
```

We've got CI set up so we'll automatically run the tests to make sure nothing's broken.

# Contributing
We love open source contribution so feel free to get involved. Ways you can contribute:
- Reporting a bug
- Discussing the current state of the code
- Proposing new features
- Submitting a fix
- Becoming a maintainer

## Reporting a bug
We use GitHub issues to track bugs. Report a bug by opening a [new bug](https://github.com/OpenBankingToolkit/jwkms/issues/new?assignees=&labels=&template=bug_report.md&title=)

## Proposing new features
We use GitHub issues to track new features. Request a new feature by opening a [new feature](https://github.com/OpenBankingToolkit/jwkms/issues/new?assignees=&labels=&template=feature.md&title=)

## Submitting a fix
Think you can fix and issue or implement a new feature? Great! 
1. Start by creating a new branch `git checkout -b fix-that-issue`
1. Make your changes
1. Add some tests
1. Raise a PR
1. Check the build passes

## Extending
We've designed the service to be extensible, this means you can take what exists today and add to it yourself. Given you've added the dependency go ahead and create your main class.

```
@SpringBootApplication
@EnableSwagger2
@EnableScheduling
@ComponentScan(basePackages = {"com.forgerock"})
@EnableMongoRepositories(basePackages = "com.forgerock")
public class Application  {

    public static void main(String[] args) throws Exception {
        new SpringApplication(ForgerockOpenbankingJwkMSApplication.class).run(args);
    }
}
```

Now you can add your own REST APIs with the `@RequestMapping` spring MVC annotations or customise behaviour such as authentication. We suggest you checkout the [sample app](https://github.com/OpenBankingToolkit/openbanking-jwkms/blob/master/forgerock-openbanking-jwkms-sample/src/main/java/com/forgerock/openbanking/jwkms/ForgerockOpenbankingJwkMSApplication.java)
