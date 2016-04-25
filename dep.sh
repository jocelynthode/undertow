#!/bin/bash

mvn install:install-file -Dfile=./tomcat-juli.jar -DgroupId=org.apache.tomcat -DartifactId=tomcat-juli -Dversion=1.0 -Dpackaging=jar;
mvn install:install-file -Dfile=./tomcat-util.jar -DgroupId=org.apache.tomcat -DartifactId=tomcat-util -Dversion=1.0 -Dpackaging=jar;
mvn install:install-file -Dfile=./tomcat-jni.jar -DgroupId=org.apache.tomcat -DartifactId=tomcat-jni -Dversion=1.0 -Dpackaging=jar;
