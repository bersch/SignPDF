#!/bin/bash
# vim:enc=latin1:tenc=latin1

if [ -z $1 ]; then
echo "Usage: $0 <CA cert PEM file>"
  exit 1
fi

CACERT=$1
BCJAR=/usr/share/java/bcprov.jar

STOREPASS=yourpassword


TRUSTSTORE=.keystore
ALIAS=`openssl x509 -inform PEM -subject_hash -noout -in "$CACERT"`

rm "$TRUSTSTORE" 

echo "Adding certificate to $TRUSTSTORE..."
keytool -import -v -trustcacerts -alias $ALIAS \
      -file $CACERT \
      -keystore $TRUSTSTORE \
	  -storepass $STOREPASS

echo ""
echo "Added '$CACERT' with alias '$ALIAS' to $TRUSTSTORE..."

echo "checking ..."

keytool -list -keystore "$TRUSTSTORE" -storepass $STOREPASS

