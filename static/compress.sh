#!/bin/sh
for f in $(ls app/*.js | egrep -v 'min.js$' | xargs); do
        n=$(dirname $f)/$(basename $f .js).min.js
        python -m jsmin $f > $n
done
for f in $(ls controllers/*.js | egrep -v 'min.js$' | xargs); do
        n=$(dirname $f)/$(basename $f .js).min.js
        python -m jsmin $f > $n
done
find . | egrep '\.(html|map|svg|ttf|css|js)$' | xargs gzip -9kf 
