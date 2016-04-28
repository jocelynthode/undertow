#!/bin/bash

# Path to tomcat repo (built)
TOMCAT="$1"

mvn install:install-file "-Dfile=$TOMCAT/output/build/bin/tomcat-juli.jar" -DgroupId=org.apache.tomcat -DartifactId=tomcat-juli -Dversion=1.0 -Dpackaging=jar;
mvn install:install-file "-Dfile=$TOMCAT/output/build/lib/tomcat-util.jar" -DgroupId=org.apache.tomcat -DartifactId=tomcat-util -Dversion=1.0 -Dpackaging=jar;
mvn install:install-file "-Dfile=$TOMCAT/output/build/lib/tomcat-jni.jar" -DgroupId=org.apache.tomcat -DartifactId=tomcat-jni -Dversion=1.0 -Dpackaging=jar;
mvn install:install-file "-Dfile=$TOMCAT/output/build/lib/tomcat-coyote.jar" -DgroupId=org.apache.tomcat -DartifactId=tomcat-coyote -Dversion=1.0 -Dpackaging=jar;
