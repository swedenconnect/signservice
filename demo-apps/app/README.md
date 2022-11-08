![Logo](../../docs/images/sweden-connect.png)


# SignService Demo Application

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

-----

A SignService application for test and demonstration.

## About

The SignService Demo Application is a Spring Boot application making use of the [SignService Spring Boot Starter](../../spring-boot-starter/README.md). Its main purpose is to illustrate how an application is configured and how few lines of code you actually have to write yourself... if you use Spring Boot ;-)

You can run the application locally on your machine and it has two configured clients:

- `test-my-signature-localhost` - The GitHub repo [signservice-integration](https://github.com/idsec-solutions/signservice-integration) provides a test client that authenticates the user against the Sweden Connect Sandbox
federation and sends a SignRequest message to our local SignService application, see "Setting up Test my Signature" below.

- `signservice-test-localhost` - Under https://sig.sandbox.swedenconnect.se/testsp you'll find the Signature Service
Test Application that is an online test client for a number of different signature services. If you logon using the
username 'signserviceuser' and the password 'signserviceuser' and select **Sweden Connect SignService V2 Localhost** you can use this application
to test your SignService running locally on your machine.

### Running the SignService Application

After the entire repository has been built it should be possible to start the SignService Demo Application ...

Start the application with its default settings. You only need to specify a variable named `SIGNSERVICE_HOME` pointing at the SignService data directory (where audit logs, and CA files are stored).

```
> cd ${signservice-dir}
>
> java -jar app/target/signservice-demo-<current-version>.jar --SIGNSERVICE_HOME="/my/path/to/the/datadir"

```

**Note:** The SignService application will listen on port 8443.


### Setting up Test my Signature

In order to use the demo "Test my Signature" client application locally on your machine follow the below steps:

**Step 1:** Clone the [signature-integration](https://github.com/idsec-solutions/signservice-integration) repository.

```
> git clone https://github.com/idsec-solutions/signservice-integration.git
```

**Step 2:** Build the SignService integration code (the test application is built after the main code).

```
> cd signservice-integration
> mvn clean install
> ...
> cd test-my-signature
> mvn clean package
```

**Step 3:** Run the application with the profiles `sandbox` ,`sign` and `localhost` active.

```
> java -jar target/test-my-signature-1.3.3-SNAPSHOT.jar --spring.profiles.active=sandbox,sign,localhost
```

Note: The application will listen to port 9445. If you want to change this pass in another value for the `server.port` setting, or open the project in your IDE and make the changes you like.

**Step 4:** Open `https://localhost:9445/testmyeid` in your browser.

> Note: Your browser will warn for the self-signed TLS certificate presented. Allow this certificate to continue.

**Step 5:** Authenticate a user and then sign...

> Note: Use the Sweden Connect Reference IdP if you don't have any credentials for any other IdP:s. The Sweden
Connect Reference IdP lets you simulate the authentication.


-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
