/**
 * Created by pawelkrawczyk on 26/09/2014.
 */

"use strict";

cspControllers.controller('CspSessionController', ['$scope', '$cookieStore', '$window', '$rootScope',
    function ($scope, $cookieStore, $window, $rootScope) {

        // check if user is logged in
        var owner_id = $cookieStore.get('owner_id');
        console.log('CspSessionController owner_id=' + owner_id)
        if (!owner_id) {
            $window.location.href = '/static/#/login';
        }
        $rootScope.owner_id = owner_id;

        $scope.logout = function () {
            console.log('CspSessionController logout');
            delete $rootScope.owner_id;
            $cookieStore.remove('owner_id');
            $cookieStore.remove('XSRF-TOKEN');
            //$window.location.href = '/';
        }

}]);