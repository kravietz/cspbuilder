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
        // need to decode from hex
        var ns = "";
        for(var i=0; i < s.length; i += 2) { ns += String.fromCharCode(parseInt(s.substr(i, 2), 16)); }
        $rootScope.owner_id = ns;

        $scope.logout = function () {
            console.log('CspSessionController logout');
            delete $rootScope.owner_id;
            $cookieStore.remove('owner_id');
            $cookieStore.remove('XSRF-TOKEN');
            //$window.location.href = '/';
        }

}]);