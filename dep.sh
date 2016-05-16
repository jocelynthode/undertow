#!/bin/bash

# Path to tomcat repo (built)
TCN2="$1"

mvn install:install-file "-Dfile=$TCN2/dist/tomcat-native-1.2.5.jar" -DgroupId=org.apache.tomcat -DartifactId=tomcat-native2 -Dversion=1.0 -Dpackaging=jar;
