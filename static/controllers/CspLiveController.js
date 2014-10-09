/**
 * Created by pawelkrawczyk on 08/10/2014.
 */

/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

cspControllers.controller('CspLiveController', ['$scope', '$rootScope', '$interval', '$http',
    function ($scope, $rootScope, $interval, $http) {
        "use strict";

        console.log('CspLiveController owner_id=' + $rootScope.owner_id);
        mixpanel.track("View live");

        $scope.reports = [];
        var last_seq = null;

        var promise = $interval(function () {
            poll();
        }, 2000);

        function poll() {
            // build changes feed URL with parameters
            var req = '/csp/_changes';
            req += '?descending=true&';
            req += 'feed=longpoll';
            req += '&filter=csp/owner';
            req += '&limit=10';
            req += '&owner_id=' + $rootScope.owner_id;
            // not on first call
            if (last_seq) {
                req += '&last_seq=' + last_seq;
            }
            $http.get(req)
                .success(function (data, status, headers, config) {
                    console.log('get', data);
                    $scope.reports.push(data.results);
                    last_seq = data.last_seq;
                })
                .error(function (data, status, headers, config) {
                    $scope.error = data;
                });

        };

        $scope.stop = function () {
            console.log('Cancelled');
            $interval.cancel(promise);
        }

    }
]);