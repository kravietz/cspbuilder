/**
 * Created by pawelkrawczyk on 09/09/2014.
 */

"use strict";

cspControllers.controller('CspKnownController', ['$scope', 'cornercouch', '$cookieStore',
    function ($scope, cornercouch) {
        console.log('CspKnownController');

        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.db.query("csp", "known_list",
            {
                include_docs: true,
                key: $scope.owner_id
            })
            .success(function () {
                console.log('data loading finished');

                // sort entries by action
                $scope.db.rows.sort(function (a, b) {
                    return a.key[3] - b.key[3];
                });

                $scope.blocked = false;
            })
            .error(function(resp) {
                $scope.blocked = false;
                $scope.error = resp;
            });

    }
]);