#!/bin/sh
find . -type f -name '*.js' -exec gzip -9fk {} \;
find . -type f -name '*.html' -exec gzip -9fk {} \;
find . -type f -name '*.css' -exec gzip -9fk {} \;
find . -type f -name '*.map' -exec gzip -9fk {} \;
