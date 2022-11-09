![Logo](images/sweden-connect.png)

# Setting up a Signature Service Application

A Signature Service application can be deployed in two fashions; as a frontend/backend deployment and as
a compound application acting both as a frontend and a backend service.

The benefits of having a separate frontend is that it is possible to deploy the sensitive backend
application in a more protected area (network wise). The drawback is that the deployment is slightly
more complex and requires REST API-calls from the frontend to the backend. 

> Note: The communication between a frontend and a backend service needs to be protected. How this is
done is not covered in this repository.

The **signservice** repository contains [sample applications](https://github.com/swedenconnect/signservice/tree/main/demo-apps) that illustrate what needs to be done in order to set up a SignService application using
the modules of the repository.

## Compound Deployment

Basically, what is needed to get access to all logic and functionality is to create a
[SignServiceEngineManager](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/engine/SignServiceEngineManager.java) object. The 
[config module](https://github.com/swedenconnect/signservice/tree/main/config/base) and
the documentation of [Signature Service Configuration](https://docs.swedenconnect.se/signservice/configuration.html) describes how to configure an application and how to create the engine
manager.

### The Controller

Once the [SignServiceEngineManager](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/engine/SignServiceEngineManager.java) object has been created
it should get to work. The Spring Boot example below illustrates how a simple controller invokes 
the manager to process sign request messages and other requests sent to the application.

```
@Controller
@Slf4j
public class SignServiceController {

  /** The session attribute name for storing the SignService context. */
  private static final String SIGNSERVICE_CONTEXT_NAME = SignServiceContext.class.getPackageName() + ".Context";

  @Setter
  @Autowired
  private SignServiceEngineManager manager;

1 @RequestMapping("/sign/**")
  public ModelAndView processRequest(final HttpServletRequest request, final HttpServletResponse response)
2     throws UnrecoverableSignServiceException {

    final HttpSession session = request.getSession();
3   final SignServiceContext context = (SignServiceContext) session.getAttribute(SIGNSERVICE_CONTEXT_NAME);

4   final SignServiceProcessingResult result =
        this.manager.processRequest(new ServletApiHttpUserRequest(request), context);

5   if (result.getSignServiceContext() == null) {
      session.removeAttribute(SIGNSERVICE_CONTEXT_NAME);
    }
    else {
      session.setAttribute(SIGNSERVICE_CONTEXT_NAME, result.getSignServiceContext());
    }

6   if (result.getResponseAction().getBody() != null) {
      result.getResponseAction().getBody().getHeaders().forEach((n, v) -> response.addHeader(n, v));
      
      try {
        response.getOutputStream().write(result.getResponseAction().getBody().getContents());
        response.flushBuffer();
        return null;
      }
      catch (final IOException e) {
        final String msg = String.format("Failed to write resource %s - %s", request.getRequestURI(), e.getMessage());
        log.info("{}", msg, e);
        throw new UnrecoverableSignServiceException(UnrecoverableErrorCodes.INTERNAL_ERROR, msg, e);
      }
    }

7   if (result.getResponseAction().getRedirect() != null) {
      return new ModelAndView("redirect:" + result.getResponseAction().getRedirect().getUrl());
    }

8   if (result.getResponseAction().getPost() != null) {
      final ModelAndView mav = new ModelAndView("post");
      mav.addObject("action", result.getResponseAction().getPost().getUrl());
      mav.addObject("parameters", result.getResponseAction().getPost().getParameters());
      return mav;
    }

    // Will never happen. The response action will always contain any of the three above options ...
    //
    throw new UnrecoverableSignServiceException(UnrecoverableErrorCodes.INTERNAL_ERROR, "Invalid backend response");
  }

}
```

So, what is happening here?

1. We tell our MVC-framework that we accept all requests starting with `/sign`. Make sure that the
application configuration matches this path. 

2. An `UnrecoverableSignServiceException` may be thrown by the manager. It only throws this exception if it can not figure a way to send back a response message to the requesting client. The application must have an error handler that takes care of this exception and translates it to an error page that is displayed to the user.

3. The controller is responsible of maintaining the SignService context (and supplying this is process calls). So, for
each call the controller will get the context from the user session. For "new" requests no context will be available.

4. We invoke the manager that will dispatch the request to the correct SignService engine (based on
the path on which the request was received). The result is a [SignServiceProcessingResult](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/core/application/SignServiceProcessingResult.java) object.

5. Before acting on the result, the controller updates the SignService context (i.e., the user state). If `null` the context is cleared, and otherwise it is updated (for more calls in a signature operation).

6. If the result contains a "body" it means that the request was not a sign request message but a request
for another resource (for example a GET-request for SAML SP metadata). The engine that received this
request will then set a "body" that the controller writes to the `HttpServletResponse`.

7. The result means that we should redirect the user to the given URL. This can happen when the
user is directed to an authentication service (Identity Provider) for authentication during the
signature process.

8. The result means that we should post the user to the given URL with the supplied parameters. This
typically happens when the signature service is complete and a response message is posted back to
the client.

Check out the [sample application](https://github.com/swedenconnect/signservice/tree/main/demo-apps) for 
a complate and working application.

## Frontend/backend Deployment

A SignService backend is configured in nearly the same way as the compound application (see above). The
only difference is that a different controller is used to accept requests. Instead of receiving the
user's browser directly, a REST API is used and the frontend makes the calls.

The frontend application controller looks more or less like the compound controller with the exception that
a REST client call is made instead of a call to the SignServiceEngineManager.

### The Backend Controller

```
@RestController
public class SignServiceBackendController {

  @Setter
  @Autowired
  private SignServiceEngineManager manager;

1 @PostMapping(path = "/process", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public RestProcessRequestResult processRequest(@RequestBody final RestProcessRequestInput input)
      throws UnrecoverableSignServiceException {

2   final SignServiceContext context = Optional.ofNullable(input.getContext())
        .map(c -> DefaultSignServiceContext.deserialize(c))
        .orElse(null);

3   final SignServiceProcessingResult result =
        this.manager.processRequest(input.getUserRequest(), context);

4   return new RestProcessRequestResult(result);
  }

}
```

1. The backend will accept POST calls with JSON content on `/process`.

2. The SignService context is supplied in the input and the backend deserializes it into a `SignServiceContext` object-

3. A call to the SignService engine manager is made in the same way the compound controller invokes the manager.

4. The result is wrapped in a JSON structure and returned.

### The Frontend Controller

```
@Controller
public class SignServiceFrontendController {

  private static final String SIGNSERVICE_CONTEXT_NAME = SignServiceContext.class.getPackageName() + ".Context";

  @Autowired
  @Setter
  private RestTemplate restTemplate;

  @Autowired
  @Setter
  private SignServiceFrontendConfigurationProperties config;

  @RequestMapping("/sign/**")
  public ModelAndView processRequest(final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, RestClientException {

    final HttpSession session = request.getSession();
    final String context = (String) session.getAttribute(SIGNSERVICE_CONTEXT_NAME);

    final RestProcessRequestResult result;
    try {
      result = this.restTemplate.postForObject(
          this.config.getBackendUrl() + this.config.getProcessPath(),
          new RestProcessRequestInput(context, new ServletApiHttpUserRequest(request)),
          RestProcessRequestResult.class);
    }
    catch (final RestClientException e) {
      // If we got an error, we remove the context from the session ...
      session.removeAttribute(SIGNSERVICE_CONTEXT_NAME);
      throw e;
    }

    if (result.getContext() == null) {
      session.removeAttribute(SIGNSERVICE_CONTEXT_NAME);
    }
    else {
      session.setAttribute(SIGNSERVICE_CONTEXT_NAME, result.getContext());
    }

    if (result.getResponseAction().getBody() != null) {
      result.getResponseAction().getBody().getHeaders().forEach((n, v) -> response.addHeader(n, v));

      response.getOutputStream().write(result.getResponseAction().getBody().getContents());
      response.flushBuffer();
      return null;
    }

    if (result.getResponseAction().getRedirect() != null) {
      return new ModelAndView("redirect:" + result.getResponseAction().getRedirect().getUrl());
    }

    if (result.getResponseAction().getPost() != null) {
      final ModelAndView mav = new ModelAndView("post");
      mav.addObject("action", result.getResponseAction().getPost().getUrl());
      mav.addObject("parameters", result.getResponseAction().getPost().getParameters());
      return mav;
    }

    throw new IOException("Invalid backend response");
  }

}
```

This controller basically looks like the controller for the compound application. The only difference
is the following snippet:

```
    final RestProcessRequestResult result;
    try {
      result = this.restTemplate.postForObject(
          this.config.getBackendUrl() + this.config.getProcessPath(),
          new RestProcessRequestInput(context, new ServletApiHttpUserRequest(request)),
          RestProcessRequestResult.class);
    }
    catch (final RestClientException e) {
      // If we got an error, we remove the context from the session ...
      session.removeAttribute(SIGNSERVICE_CONTEXT_NAME);
      throw e;
    }
```

Instead of making a call to the SignService engine manager a REST client call is made.


## Productionalization

High availability, load balancing, and clustering are topics that we face when going to a
production environment. If we are to run our applications with load balancing where several
SignService application instances are running there are a few things to point out related to
the SignService [configuration](https://docs.swedenconnect.se/signservice/configuration.html).

- The application session handling must be able to handle distributed sessions. <br /><br />
For a Spring setup, using [Spring Session](https://spring.io/projects/spring-session) together
with for example Redis should solve everything and the default session object can be used.

- The [MessageReplayChecker](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/MessageReplayChecker.java) in use must have a distributed storage.
<br /><br />
The [DefaultMessageReplayChecker](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/impl/DefaultMessageReplayChecker.java) class can be used, but it needs to be supplied a [ReplayCheckerStorageContainer](https://github.com/swedenconnect/signservice/blob/main/core/src/main/java/se/swedenconnect/signservice/storage/impl/ReplayCheckerStorageContainer.java) instance that is distributed. The SignService repository only supplies an in-memory version of this class, and it is up to the application developers to implement a storage container that matches the application's chosen distribution solution.

- The use of a Hardware Security Module (HSM). <br /><br />
The [credentials-support](https://github.com/swedenconnect/credentials-support) module that is used by the SignService modules offers support for configuring a `PkiCredential` to use a HSM (instead of software based keys). It is also possible to configure the `CredentialContainer` used by the key and certificate handlers to generate keys in hardware. See [CredentialContainer Configuration](https://github.com/swedenconnect/signservice/tree/main/keycert/base).

- For frontend/backend deployments the REST communication needs to be secured.

Of course there are a lot of more topics that need to be addressed for a production ready service,
but the items described above really are the only things directly associated to the SignService 
modules. Other things like backups, logging, monitoring can be handled in the application itself. 


-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

