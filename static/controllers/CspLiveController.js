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
            poll($rootScope.owner_id, last_seq);
        }, 2000);

        function poll(owner_id, last_seq) {
            var req = '/csp/_changes?descending=true&feed=longpoll&filter=csp/owner&limit=10';
            req += '&owner_id=' + owner_id;
            if (last_seq) {
                req += '&last_seq=' + last_seq;
            }
            $http.get(req)
                .success(function (data, status, headers, config) {
                    console.log('get', data);
                    $scope.reports = data.results;
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