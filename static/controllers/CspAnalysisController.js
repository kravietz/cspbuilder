/**
 * Created by Paweł Krawczyk on 04/09/2014.
 */

cspControllers.controller('CspAnalysisController', ['$scope', '$rootScope', 'cornercouch',
    function ($scope, $rootScope, cornercouch) {
        "use strict";

        console.log('CspAnalysisController owner_id=' + $rootScope.owner_id);

        $scope.blocked = true;
        $scope.db_name = get_db_for_user($rootScope.owner_id);
        $scope.reports_db = cornercouch(couchdb_url, 'GET').getDB($scope.db_name);
        // for KnownList updates
        $scope.csp_db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.index = 0;
        $scope.reports_db.query("reports", "1100_source_groups", {
            include_docs: false,
            // CouchDB idiom used to narrow search
            // ref: http://docs.couchdb.org/en/latest/couchapp/views/collation.html#string-ranges
            startkey: [$rootScope.owner_id],
            endkey: [$rootScope.owner_id, {}],
            // group & reduce required for grouping to work
            reduce: true,
            group: true
        })
            .success(function () {
                console.log('data loading finished');

                // sort
                $scope.reports_db.rows.sort(function (a, b) {
                    return b.value - a.value;
                });

                $scope.blocked = false;
            });

        mixpanel.track("View analysis");

        $scope.detail_open = function (index) {
            console.log('detail_open ' + index);
            delete $scope.policy_message;
            delete $scope.error;
            delete $scope.csp;
            delete $scope.meta;
            delete $scope.policy_type;
            delete $scope.policy_sources;
            $('#report-row-' + $scope.index).removeClass('bg-info'); // delete highlight from old row
            $scope.index = index;
            $('#report-row-' + $scope.index).addClass('bg-info'); // highlight current row
            // sources list already contains the key we can use to fetch sample report
            $scope.db2 = cornercouch(couchdb_url, 'GET').getDB($scope.db_name);
            $scope.db2.query('reports', '1100_source_groups',
                {
                    reduce: false,
                    limit: 1,
                    key: $scope.db.rows[index].key,
                    include_docs: true
                })
                .success(function () {
                    console.log('$scope.db2.rows=' + $scope.db2.rows.length);
                    if($scope.db2.rows.length) {
                        $scope.csp = $scope.db2.rows[0].doc['csp-report'];
                        $scope.meta = $scope.db2.rows[0].doc.meta;
                        $scope.policy_type = $scope.csp['effective-directive'] ? $scope.csp['effective-directive'] : $scope.csp['violated-directive'].split(' ')[0];

                        // turn report source into policy statement
                        var ret = source_to_policy_statement($scope.csp, $scope.meta);
                        $scope.policy_message = ret.message;
                        $scope.policy_sources = ret.sources;
                    } else {
                        // hide given row if no results were returned
                        $('#report-row-' + $scope.index).addClass('hidden');
                    }
                })
                .error(function (resp) {
                    $scope.error = resp;
                });

            mixpanel.track("View analysis detail");
        };   // detail_open

        $scope.review_source = function (allow) {

            console.log('review_source allow=' + allow + ' policy_choice=' + $scope.policy_choice);

            // save new KL entry
            var doc = $scope.csp_db.newDoc({
                'owner_id': $scope.owner_id,
                'review_type': $scope.policy_type,
                'review_source': $scope.policy_choice,
                'review_action': allow ? 'accept' : 'reject',
                'user_agent': navigator.userAgent,
                'timestamp': Date()
            });
            doc.save();

            // move to the next source
            console.log('review source completed');
            $('#report-row-' + $scope.index).hide();
            $scope.detail_open($scope.index + 1);

        }; // review_source

    } // function($scope
]);
