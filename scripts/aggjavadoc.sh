#!/usr/bin/env bash
#
# Helper script to build aggregated Javadoc. The normal way of doing it
# won't work since we use delombok.
#

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $SCRIPT_DIR/..

mvn clean install -Prelease -DskipTests

JDDIR=target/javadocjars

mkdir -p $JDDIR

cp core/target/*-javadoc.jar $JDDIR
cp audit/base/target/*-javadoc.jar $JDDIR
cp audit/actuator/target/*-javadoc.jar $JDDIR
cp authn/base/target/*-javadoc.jar $JDDIR
cp authn/saml/target/*-javadoc.jar $JDDIR
cp protocol/dss-ext11/target/*-javadoc.jar $JDDIR
cp signhandler/target/*-javadoc.jar $JDDIR
cp keycert/base/target/*-javadoc.jar $JDDIR
cp keycert/simple/target/*-javadoc.jar $JDDIR
cp engine/target/*-javadoc.jar $JDDIR
cp config/base/target/*-javadoc.jar $JDDIR
cp config/spring/target/*-javadoc.jar $JDDIR
cp spring-boot-starter/target/*-javadoc.jar $JDDIR

mvn package javadoc:aggregate -Paggjavadoc -DskipTests

for JDF in $JDDIR/*.jar; do
  [ -e "$JDF" ] || continue
  echo "Processing $JDF"
  rm -rf $JDDIR/tmp
  mkdir -p $JDDIR/tmp
  mv $JDF $JDDIR/tmp
  pushd $JDDIR/tmp
  jar xvf *-javadoc.jar
  cp -r se ../../site/apidocs/
  popd
done

rm -rf $JDDIR

rm -rf docs/apidocs/*
mkdir -p docs/apidocs
cp -r target/site/apidocs/* docs/apidocs
