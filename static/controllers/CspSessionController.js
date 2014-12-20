/**
 * Created by Paweł Krawczyk on 26/09/2014.
 */

cspControllers.controller('CspSessionController', ['$scope', '$cookies', '$window', '$rootScope',
    function ($scope, $cookies, $window, $rootScope) {
        "use strict";

        // track page view, this should be called on each page including main
        mixpanel.track("Page view");

        // check if user is logged in
        var owner_id = $cookies.owner_id;
        console.log('CspSessionController owner_id=' + owner_id + ' (encoded)');
        if (owner_id) {
            // decode owner_id from BASE64 and store in root scope
            $rootScope.owner_id = owner_id;
            console.log('CspSessionController owner_id=' + $rootScope.owner_id + ' (decoded)');
        }

        $scope.logout = function () {
            console.log('CspSessionController logout');
            console.log('logout coookies before=' + document.cookie);
            delete $rootScope.owner_id;
            delete $cookies.owner_id;
            delete $cookies['XSRF-TOKEN'];
            $window.location.href = '/';
            console.log('logout coookies after=' + document.cookie);
        }

}]);