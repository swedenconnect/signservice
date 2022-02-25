![Logo](images/sweden-connect.png)


# Signature Service Internal Documentation

> Contains documents and information that are internal to the project and not published on the Web (/docs).

## Presentations

- Presentation from project kick-off - [20220215-Kick-off.pdf](archive/20220215-Kick-off.pdf)

## Planning

The project planning is performed using Jira outside of this repository, so this repo doesn't contain any
milestones or tasks. However, the following milestones have been defined:

- Milestone 1 - Structure and design
  - Design and architechture is in place.
  - A runnable SignService application exists.
  - General code structure including build and CI is in place.
  - The "engine"-module is completed.
  - Other modules and handlers exist in default, or mocked implementations.
  
- Milestone 2 - Ready to release as open source
  - All modules and handlers are completed and tested, including CA. Ready for production.
  - Documentation such as architechtural descriptions, Javadoc and configuration documentation is ready.
  
- Milestone 3 - Deployment
  - Deployment of a SignService application according to DIGG's requirements.
  - Education
  - Supervision, PEN-testing, ...
  - Setup of an acceptance testing environment
  - Deploy- and project documentation
  

## Design Documents

* [Signature Service Design Documentation](Design.md)

## Code Style

All developers contributing to this project should follow the [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html). Read it!

### Code Style Templates

* Eclipse: [eclipse-java-google-style.xml](eclipse-java-google-style.xml)
* IntelliJ: [intellij-java-google-style.xml](intellij-java-google-style.xml)

### MIT License Header

Include the following header in all Java files:

```
/*
 * MIT License
 * 
 * Copyright 2022 Sweden Connect
 */
```

Configure Eclipse or IntelliJ to do it automatically!
