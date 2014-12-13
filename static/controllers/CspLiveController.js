/**
 * Created by pawelkrawczyk on 08/10/2014.
 */

/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

cspControllers.controller('CspLiveController', ['$scope', '$rootScope', '$timeout', '$http', 'cornercouch',
    function ($scope, $rootScope, $timeout, $http, cornercouch) {
        "use strict";

        console.log('CspLiveController owner_id=' + $rootScope.owner_id);
        mixpanel.track("View live");

        $scope.reports = [];
        $scope.polling = false;
        $scope.live_enabled = false;

        var last_seq = null;
        var poll_interval = 1000; // every 1 second
        var db = cornercouch(couchdb_url, 'GET').getDB('csp');

        $scope.poll = function () {
            $scope.live_enabled = true;
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
            console.log('polling...');
            $scope.polling = true;

            // speak to CouchDB polling API
            // http://docs.couchdb.org/en/latest/api/database/changes.html
            $http.get(req)
                .success(function (data) {
                    console.log('poll received', data);
                    $scope.polling = false;

                    if (typeof(data) == 'object') {
                        // the response has data.response and data.last_seq
                        // results is an an array of objects
                        data.results.forEach(function (item) {
                            if (item) {
                                var id = item.id;
                                $scope.reports.push(db.getDoc(id));
                            }
                        });
                    last_seq = data.last_seq;
                    }

                    // schedule next check
                    if ($scope.live_enabled) {
                        $timeout(poll, poll_interval);
                    }
                })
                .error(function (data) {
                    $scope.error = data;
                    $scope.polling = false;
                });

        };

    }
]);