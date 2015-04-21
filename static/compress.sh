#!/bin/sh
for f in $(ls app/*.js | egrep -v 'min.js$' | xargs); do
        n=$(dirname $f)/$(basename $f .js).min.js
        python -m jsmin $f > $n
done
for f in $(ls controllers/*.js | egrep -v 'min.js$' | xargs); do
        n=$(dirname $f)/$(basename $f .js).min.js
        python -m jsmin $f > $n
done
find . | egrep '\.(html|map|svg|ttf|css|js|woff|woff2)$' | xargs gzip -9kf 
cp logo.png apple-touch-icon.png
cp apple-touch-icon.png touch-icon-ipad.png
cp apple-touch-icon.png touch-icon-iphone-retina.png
cp apple-touch-icon.png touch-icon-ipad-retina.png
mogrify -geometry 76x76 touch-icon-ipad.png
mogrify -geometry 120x120 touch-icon-iphone-retina.png
mogrify -geometry 152x152 touch-icon-ipad-retina.png
