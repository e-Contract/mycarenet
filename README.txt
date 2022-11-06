README for Java MyCareNet Project
=================================

=== 1. Introduction

This project contains the source code tree of Java MyCareNet Project.
The source code is hosted at: https://github.com/e-Contract/mycarenet


=== 2. Requirements

The following is required for compiling the software:
* Java 1.8.0_351
* Apache Maven 3.8.6


=== 3. Build

The project can be build via:
	mvn clean install

Code formatting before commit via:
mvn -e com.googlecode.maven-java-formatter-plugin:maven-java-formatter-plugin:format


=== 4. Release

Release the project via:
	mvn release:prepare
	mvn release:perform


=== 5. License

The license conditions can be found in the file: LICENSE.txt
