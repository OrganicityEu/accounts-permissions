# Account Permissions

## Dependencies

Install this maven dependency (or import it into your IDE):

https://github.com/OrganicityEu/java-jwt-parser

## Install

Copy `Config.java.example` and configure it:

```
cp src/test/java/eu/organicity/accounts/permissions/Config.java.example src/test/java/eu/organicity/accounts/permissions/Config.java
```

```
mvn install
mvn install -DskipTests # this skisps the JUnit tests
```

## Dependency

The dependency of this project:

```
<dependency>
	<groupId>eu.organicity</groupId>
	<artifactId>accounts-permissions</artifactId>
	<version>0.1.0-dev</version>
</dependency>
```


## JUnit Tests

```
mvn test
```
