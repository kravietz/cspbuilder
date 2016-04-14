/**
 * Created by Paweł Krawczyk on 09/09/2014.
 */

cspControllers.controller('CspKnownController', ['$scope', 'cornercouch', '$rootScope',
    function ($scope, cornercouch, $rootScope) {
        "use strict";

        console.log('CspKnownController owner_id=' + $rootScope.owner_id);

        // TODO: should use global list of directives
        $scope.csp_directives = ['connect-src', 'child-src', 'font-src', 'form-action', 'frame-ancestors', 'frame-src',
            'img-src', 'media-src', 'object-src', 'script-src', 'style-src'];

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

        $scope.kl_save_custom = function (custom) {
            var doc = $scope.db.newDoc({
                'owner_id': $scope.owner_id,
                'review_type': custom.directive,
                'review_source': custom.origin,
                'review_action': custom.action,
                'user_agent': navigator.userAgent,
                'timestamp': Date()
            });
            doc.save();
        };

        $scope.delete_kl_entry = function (index) {
            console.log('delete_kl_entry ' + index);
            var doc = $scope.db.getQueryDoc(index);
            doc.remove();
            $('#report-row-' + index).hide();
        };

    }
]);
