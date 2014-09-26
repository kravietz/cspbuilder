/**
 * Created by pawelkrawczyk on 26/09/2014.
 */

"use strict";

cspControllers.controller('CspSessionController', ['$scope', '$cookieStore', '$window',
    function ($scope, $cookieStore, $window) {

        // check if user is logged in
        $scope.owner_id = $cookieStore.get('owner_id');
        if (!$scope.owner_id) {
            $window.location.href = '/static/#/login';
        }

}]);