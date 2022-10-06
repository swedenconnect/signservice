![Logo](../docs/images/sweden-connect.png)


# signservice/bom

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-bom/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.signservice/signservice-bom)

-----

## About

The SignService BOM (Bill of Materials) is a Maven POM that should be imported in an application's
POM file to get all the latest stable versions of SignService modules. The usage of the BOM also
prevents dependency convergence errors.

## Usage

In the SignService application POM include the following:

```
<dependencyManagement>
  <dependencies>
    
    <dependency>
      <groupId>se.swedenconnect.signservice</groupId>
      <artifactId>signservice-bom</artifactId>
      <type>pom</type>
      <version>${signservice-bom.version}</version>
      <scope>import</scope>
    </dependency>

  </dependencies>    
</dependencyManagement>

```


-----

Copyright &copy; 2022, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).