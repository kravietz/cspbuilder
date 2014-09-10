/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

"use strict";

cspControllers.controller('CspAnalysisController', ['$scope', '$cookieStore', 'cornercouch', '$window', '$http',
    function ($scope, $cookieStore, cornercouch, $window, $http) {

        $scope.owner_id = $cookieStore.get('owner_id');
        if (!$scope.owner_id) {
            $window.location.href = '/static/#/login';
        }

        $scope.blocked = true;
        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.index = 0;
        $scope.db.query("csp", "grouped_types_sources", {
            include_docs: false,
            // CouchDB idiom used to narrow search
            // ref: http://docs.couchdb.org/en/latest/couchapp/views/collation.html#string-ranges
            startkey: [$scope.owner_id],
            endkey: [$scope.owner_id, {}],
            // group & reduce required for grouping to work
            reduce: true,
            group: true
        })
            .success(function () {
                console.log('data loading finished');
                $scope.db.rows.sort(function (a, b) {
                    return a.value - b.value;
                });
                $scope.blocked = false;
            });

        $scope.logout = function () {
            console.log('logout');
            $cookieStore.remove('owner_id');
            $window.location.href = '/static/#/login';
        };

        $scope.detail_open = function (index) {
            console.log('detail_open ' + index);
            $scope.policy_message = null;
            $scope.reviewed = false;
            $('#report-row-' + $scope.index).removeClass('bg-info'); // delete highlight from old row
            $scope.index = index;
            $('#report-row-' + $scope.index).addClass('bg-info'); // highlight current row
            // sources list already contains the key we can use to fetch sample report
            $scope.db2 = cornercouch(couchdb_url, 'GET').getDB('csp');
            $scope.db2.query('csp', 'grouped_types_sources',
                {
                    reduce: false,
                    limit: 1,
                    key: $scope.db.rows[index].key, // endkey not needed because limit=1
                    include_docs: true
                })
                .success(function () {
                    $scope.csp = $scope.db2.rows[0].doc['csp-report'];
                    $scope.meta = $scope.db2.rows[0].doc.meta;
                    $scope.policy_type = $scope.csp['violated-directive'].split(' ')[0];

                    // turn report source into policy statement
                    var ret = source_to_policy_statement($scope.csp);
                    $scope.policy_message = ret.message;
                    $scope.policy_sources = ret.sources;
                })
                .error(function (resp) {
                    $scope.error = resp;
                });
        };   // detail_open

        $scope.review_source = function (allow) {

            console.log('review_source allow=' + allow + ' policy_choice=' + $scope.policy_choice);

            $http.post('/api/' + $scope.owner_id + '/review', {
                    'review_type': $scope.policy_type,
                    'review_source': $scope.policy_choice,
                    'review_action': allow ? 'accept' : 'reject'
                })
                .error(function (error) {
                    $scope.error = error;
                })
                .success(function () {
                    console.log('review source completed');
                    $scope.reviewed = true;
                    // add green tick in details tab
                    // TODO: fix HTML selectors
                    //$('input:checked').parent().add('span').addClass('text-success glyphicon glyphicon-ok');
                    // highlight processed row according to its state
                    if (allow) {
                        $('#report-row-' + $scope.index).addClass('bg-success');
                    } else {
                        $('#report-row-' + $scope.index).addClass('bg-warning');
                    }
                });

        }; // review_source

    } // function($scope
]);
