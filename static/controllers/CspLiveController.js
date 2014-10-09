/**
 * Created by pawelkrawczyk on 08/10/2014.
 */

/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

cspControllers.controller('CspLiveController', ['$scope', '$rootScope', '$timeout', '$http',
    function ($scope, $rootScope, $timeout, $http) {
        "use strict";

        console.log('CspLiveController owner_id=' + $rootScope.owner_id);
        mixpanel.track("View live");

        $scope.reports = [];
        var last_seq = null;

        // start polling
        poll();

        function poll() {
            // build changes feed URL with parameters
            var req = '/csp/_changes';
            req += '?descending=true&';
            req += 'feed=longpoll';
            req += '&filter=csp/owner';
            req += '&limit=10';
            req += '&owner_id=' + $rootScope.owner_id;
            // only on subsequent calls
            if (last_seq) {
                req += '&last_seq=' + last_seq;
            }
            $http.get(req)
                .success(function (data) {
                    console.log('poll received', data);
                    $scope.reports.push(data.results);
                    last_seq = data.last_seq;
                    // schedule next check
                    $timeout(poll, 1000);
                })
                .error(function (data) {
                    $scope.error = data;
                });

        };

    }
]);