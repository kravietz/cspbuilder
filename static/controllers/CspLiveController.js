/**
 * Created by pawelkrawczyk on 08/10/2014.
 */

/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

cspControllers.controller('CspLiveController', ['$scope', '$rootScope', '$interval',
    function ($scope, $rootScope, $interval) {
        "use strict";

        console.log('CspLiveController owner_id=' + $rootScope.owner_id);
        mixpanel.track("View live");

        $scope.reports = [];

        var promise = $interval(function () {
            $http.get('/csp/_changes?feed=longpoll&filter=csp/owner&owner_id=' + $rootScope.owner_id)
                .success(function (data, status, headers, config) {
                    console.log('get', data);
                    $scope.reports = data.results;
                    $scope.last_seq = data.last_seq;
                })
                .error(function (data, status, headers, config) {
                    $scope.error = data;
                });
        }, 2000);

    }
]);