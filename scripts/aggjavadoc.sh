#!/usr/bin/env bash
#
# Copyright 2022-2024 Sweden Connect
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
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
