/**
 * Created by pawelkrawczyk on 26/09/2014.
 */

cspControllers.controller('CspSessionController', ['$scope', '$cookieStore', '$window', '$rootScope',
    function ($scope, $cookieStore, $window, $rootScope) { "use strict";

        // check if user is logged in
        var owner_id = $cookieStore.get('owner_id');
        console.log('CspSessionController owner_id=' + owner_id + ' (encoded)');
        if (!owner_id) {
            $window.location.href = '/static/#/login';
        }
        // need to decode
        $rootScope.owner_id = window.atob(owner_id);
        console.log('CspSessionController owner_id=' + $rootScope.owner_id + ' (decoded)')

        $scope.logout = function () {
            console.log('CspSessionController logout');
            delete $rootScope.owner_id;
            $cookieStore.remove('owner_id');
            $cookieStore.remove('XSRF-TOKEN');
            //$window.location.href = '/';
        }

}]);