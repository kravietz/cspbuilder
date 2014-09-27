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
                    if (a[1] < b[1]) return -1;
                    if (a[1] > b[1]) return 1;
                    return 0;
                });

                $scope.blocked = false;
            })
            .error(function (resp) {
                $scope.blocked = false;
                $scope.error = resp;
            });

        $scope.delete_kl_entry(function (key) {
            console.log('delete_kl_entry ' + key);
        } );

    }
]);