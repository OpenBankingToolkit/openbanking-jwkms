[<img src="https://raw.githubusercontent.com/ForgeRock/forgerock-logo-dev/master/Logo-fr-dev.png" align="right" width="220px"/>](https://developer.forgerock.com/)

| |Current Status|
|---|---|
|Build|[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2FOpenBankingToolkit%2Fopenbanking-jwkms%2Fbadge%3Fref%3Dmaster&style=flat)](https://actions-badge.atrox.dev/OpenBankingToolkit/openbanking-jwkms/goto?ref=master)|
|Code coverage|[![codecov](https://codecov.io/gh/OpenBankingToolkit/openbanking-jwkms/branch/master/graph/badge.svg)](https://codecov.io/gh/OpenBankingToolkit/openbanking-jwkms)
|Bintray|[![Bintray](https://img.shields.io/bintray/v/openbanking-toolkit/OpenBankingToolKit/openbanking-jwkms.svg?maxAge=2592000)](https://bintray.com/openbanking-toolkit/OpenBankingToolKit/openbanking-jwkms)|
|License|![license](https://img.shields.io/github/license/ACRA/acra.svg)|

**_This repository is part of the Open Banking Tool kit. If you just landed to that repository looking for our tool kit,_
_we recommend having a first read to_ https://github.com/OpenBankingToolkit/openbanking-toolkit**

ForgeRock OpenBanking JWKMS
========================

JWKMS stands for Json Web Key Management Service. The JWKMS provides you an essential key management for integrating with
other parties using JWTs as communication format.
This becomes very handy for OIDC clients for example, which wishes to use JWTs for their request parameter, the dynamic registration
or even using JWTs authentication method.
The JWKMS provides you the following features:
* provides you a transport, signing and encryption keys
* publishes those keys as public JWK under the standard format JWK_URI
* allows you to rotate your keys (previous keys still accepted for a certain window of time)
* allows you to reset your keys (previous keys are not invalid)
* Sign or/and encrypt a payload into a JWTs, using your current keys (manages the all JWTs format for you)
* Validate JWTS
* Sign detached signature JWTs (You give it a payload and returns you a detached signature JWT)
* Validate detached signature JWTs
* Download your keys as certificates

The JWKMS is able to managed asymmetric keys: EC, RS and PS

The JWKMS can be deploy in two different ways:
* Centralised JWKMS instance
* Embedded into your app


## Centralised JWKMS instance

The JWKMS can be deploy as a single dedicated instance. In that configuration, the JWKMS can manage keys for multiple
 applications at the same time. This means that your other micro-services can delegate the JWTs manipulation and JWK management
 to the JWKMS.
 A centralised JWKMS into your environment offers the following advantages:
 * Your other micro-services are lighter, in size and in resources required: Cryptography is heavy CPU demanding, by delegating
 the cryptography to the JWKMS, you can managed your resources in a more granular way. An possible optimisation could be to
 create a node affinity of the JWKMS to a specific kind of nodes designed to be  Cryptographic efficient, and having your other micro-services
 in other kind of nodes.
 * JWKMS does cryptography tasks, which needs to use the latest security fixes and optimisations. Having it centralised allows
 you to update the JWKMS without impacting your other microservices and without having to upgrade each of them.
 * The JWKMS is stateless, it can scale horizontally. If you need better crypto performances, you can avoid having to scale
 all your microservices but just scaling up the JWKMS
 * You can force all of your micro-services to rotate their keys in one place: instead of having to call all your micro-services
 independently, you only have to call the JWKMS instance to rotate all your keys
 * Changing algorithms to all your microservices is simplified: you can change the default algorithms in the jwkms instance and all
 your microservices will suddenly use it.
 
For authenticating those apps and uses their dedicated keys, you would need to define an authentication method. We
offer MATLS as one possible way to authenticate micro-services to the JWKMS


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

In smaller environment, you may not want to have a dedicated JWKMS instance but more offer a JWKMS capacity inside each apps
directly.
By embedding the JWKMS, as a Java library, your app will be able to manipulate JWTs and manage it's own key out of the box.
You will be able to call an API to sign a json into a JWTs for example.

Having it embedded requires more resources for your micro-services. From a security side of things, you will need to do more
regular upgrades or individual actions for each of your micro-services.
Read the advantages of a single micro-services to understand the implication of having it embedded instead.

The advantages of having an embedded JWKMS is that it removes a micro-service dependency. Your microservice can be
deploy on its own without relying on the availability of another one.
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

* If you are doing a POC, a test, examples, etc, definitively choose the embedded approach.

* If you are building a production environment, where you aim for best performances, scalability, easy maintenance and better
security risk management, go for the centralised approach.

* If you don't have many microservices relying on the JWKMS and you can afford spending a bit more resources by scaling each
microservices instead of just the JWKMS, go for the embedded approach.

The centralised vs embedded is really a trade off. Centralised is more flexible and more resource efficient but requires
more work in your deployment. Embedded is definitively easier to put in place but may restrict you in your scalability 
and resource management in your cluster.


# JWKMS acting as CA

The JWKMS manages keys and offers to export them as certificates.
If you are not interested by the certificate format, you can skip this section.
However if you are interested to make the JWKMS sign your keys using a specific CA, stay here!

The JKWMS uses self-signed certificate CA by default and will generate keys using this CA:
It does creat a CSR and uses the self signed certificate for getting a new key issue by this CA

If you want to use a dedicated CA, which you may in use-case where you want to expose those keys to
external parties, you would need to define the interface `JwkStoreService` and define it as the primary bean.
This will delegate the key creation to your service and you will be able to customise the key creation,
by calling your CA dedicated API for example.

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
