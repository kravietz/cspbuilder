#!/bin/sh

ANGULAR=" angular-aria.js angular-aria.min.js angular-aria.min.js.map angular-cookies.js angular-cookies.min.js angular-cookies.min.js.map angular-resource.js angular-resource.min.js angular-resource.min.js.map angular-route.js angular-route.min.js angular-route.min.js.map angular.js angular.min.js angular.min.js.map errors.json version.json"

URL="https://code.angularjs.org/1.3.15"

for f in $ANGULAR; do
    echo $f
    curl -s --compressed -O "$URL/$f"
done

echo jquery-2.1.3.js
curl -s --compressed -O http://code.jquery.com/jquery-2.1.3.js
echo jquery-2.1.3.min.map
curl -s --compressed -O http://code.jquery.com/jquery-2.1.3.min.map
echo jquery-2.1.3.min.js
curl -s --compressed -O http://code.jquery.com/jquery-2.1.3.min.js
echo mixpanel.min.js
curl -s --compressed -O https://raw.githubusercontent.com/mixpanel/mixpanel-js/master/mixpanel.min.js
