/**
 * Created by Paweł Krawczyk on 09/09/2014.
 */

cspControllers.controller('CspKnownController', ['$scope', 'cornercouch', '$rootScope', '$resource',
    function ($scope, cornercouch, $rootScope, $resource) {
        "use strict";

        console.log('CspKnownController owner_id=' + $rootScope.owner_id);

        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.db.query("csp", "1000_known_list",
            {
                include_docs: true,
                key: $rootScope.owner_id
            })
            .success(function () {
                console.log('data loading finished');

                // sort entries by action
                $scope.db.rows.sort(function (doc1, doc2) {
                    if (doc1.value[2][0] < doc2.value[2][0]) return -1;
                    if (doc1.value[2][0] > doc2.value[2][0]) return 1;
                    return 0;
                });

                $scope.blocked = false;
            })
            .error(function (resp) {
                $scope.blocked = false;
                $scope.error = resp;
            });
        mixpanel.track("View known");

        $scope.delete_kl_entry = function (index) {
            console.log('delete_kl_entry ' + index);
            var doc = $scope.db.getQueryDoc(index);
            doc.remove();
            $('#report-row-' + index).hide();
        };

    }
]);