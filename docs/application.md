![Logo](images/sweden-connect.png)

# Setting up a Signature Service Application

The https://github.com/swedenconnect/signservice repository contains a 
[demo application](https://github.com/swedenconnect/signservice/tree/main/app)
that illustrates what needs to be done in order to set up a SignService application using
the modules of the repository.

Basically, what is needed to get access to all logic and functionality is to create a
[SignServiceEngineManager](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/engine/SignServiceEngineManager.java) object. The 
[config module](https://github.com/swedenconnect/signservice/tree/main/config/base) and
the documentation of [Signature Service Configuration](https://docs.swedenconnect.se/signservice/configuration.html) describes how to configure an application and how to create the engine
manager.

## The Controller

Once the [SignServiceEngineManager](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/engine/SignServiceEngineManager.java) object has been created
it should get to work. The Spring Boot example below illustrates how a simple controller invokes 
the manager to process sign request messages and other requests sent to the application.

```
@Controller
public class SignServiceController {

  @Setter
  @Autowired
  private SignServiceEngineManager manager;

1 @RequestMapping("/sign/**")
  public ModelAndView processRequest(
    final HttpServletRequest request, 
    final HttpServletResponse response) 
2     throws UnrecoverableSignServiceException {

3   final HttpRequestMessage result = this.manager.processRequest(request, response);

    if (result == null) {
4     return null;
    }
    else {
      if ("GET".equals(result.getMethod())) {
5       return new ModelAndView("redirect:" + result.getUrl());
      }
      else { // POST
6       final ModelAndView mav = new ModelAndView("post");
        mav.addObject("action", result.getUrl());
        mav.addObject("parameters", result.getHttpParameters());
        return mav;
      }
    }
  }

}
```

So, what is happening here?

1. We tell our MVC-framework that we accept all requests starting with `/sign`. Make sure that the
application configuration matches this path. 

2. An `UnrecoverableSignServiceException` may be thrown by the manager. It only throws this exception if it can not figure a way to send back a response message to the requesting client. The application must have an error handler that takes care of this exception and translates it to an error page that is displayed to the user.

3. We invoke the manager that will dispatch the request to the correct SignService engine (based on
the path on which the request was received). The result is a [HttpRequestMessage](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/core/http/HttpRequestMessage.java).

4. If the result is `null` it means that the request was not a sign request message but a request
for another resource (for example a GET-request for SAML SP metadata). The engine that received this
request will already have written the response to the `HttpServletResponse` so our controller is
done.

5. The result means that we should redirect the user to the given URL. This can happen when the
user is directed to an authentication service (Identity Provider) for authentication during the
signature process.

6. The result means that we should post the user to the given URL with the supplied parameters. This
typically happens when the signature service is complete and a response message is posted back to
the client.

Check out the [demo application](https://github.com/swedenconnect/signservice/tree/main/app) for 
a complate and working application.

## Productionalization

High availability, load balancing, and clustering are topics that we face when going to a
production environment. If we are to run our applications with load balancing where several
SignService application instances are running there are a few things to point out related to
the SignService [configuration](https://docs.swedenconnect.se/signservice/configuration.html).

- The [SessionHandler](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/session/SessionHandler.java) must be able to handle distributed
sessions. <br /><br />
For a Spring setup, using [Spring Session](https://spring.io/projects/spring-session) together
with for example Redis should solve everything and the default session handler can be used.

- The [MessageReplayChecker](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/MessageReplayChecker.java) in use must have a distributed storage.
<br /><br />
The [DefaultMessageReplayChecker](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/impl/DefaultMessageReplayChecker.java) class can be used, but it needs to be supplied a [ReplayCheckerStorageContainer](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/impl/ReplayCheckerStorageContainer.java) instance that is distributed. The SignService repository only supplies an in-memory version of this class, and it is up to the application developers to implement a storage container that matches the application's chosen distribution solution.

- The use of a Hardware Security Module (HSM). <br /><br />
The [credentials-support](https://github.com/swedenconnect/credentials-support) module that is used by the SignService modules offers support for configuring a `PkiCredential` to use a HSM (instead of software based keys). It is also possible to configure the `CredentialContainer` used by the key and certificate handlers to generate keys in hardware. See [CredentialContainer Configuration](https://github.com/swedenconnect/signservice/tree/main/keycert/base).

Of course there are a lot of more topics that need to be addressed for a production ready service,
but the items described above really are the only things directly associated to the SignService 
modules. Other things like backups, logging, monitoring can be handled in the application itself. 


-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

