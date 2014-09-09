/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

"use strict";

cspControllers.controller('CspAnalysisController', ['$scope', '$cookieStore', 'cornercouch', '$window',
    function ($scope, $cookieStore, cornercouch, $window) {

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

        $scope.detail_close = function () {
            console.log('detail_close ');
            delete $scope.meta; // hides details window
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
            console.warn('key=' + $scope.db.rows[index].key);
            $scope.db2.query('csp', 'by_source_type',
                {
                    limit: 1,
                    startkey: $scope.db.rows[index].key, // endkey not needed because limit=1
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
                .error(function(resp) {
                    $scope.error = resp;
                });
        };   // detail_open

        $scope.review_source = function (allow) {

            console.log('review_source allow=' + allow + ' policy_choice=' + $scope.policy_choice);

            // highlight processed row according to its state
            if (allow) {
                $('#report-row-' + $scope.index).addClass('bg-success');
            } else {
                $('#report-row-' + $scope.index).addClass('bg-warning');
            }

            // save new whitelist/blacklist entry if action was to allow
            var db2 = cornercouch(couchdb_url, 'GET').getDB('csp');
            var newdoc = {  'owner_id': $scope.owner_id,
                        'known_uri': $scope.policy_choice,
                        'known_type': $scope.policy_type,
                        'action': allow ? 'accept' : 'reject'
            };
            db2.newDoc(newdoc).save().error(function(resp) {
                    $scope.error = resp;
                });

            // mark as approved on the page
            $scope.reviewed = true;

            // set all reports with this key as reviewed
            $scope.db2.query('csp', 'by_source_type', {
                key: [$scope.owner_id, $scope.policy_type, $scope.policy_choice],
                include_docs: true
            })
            .success(function () {
                var approve_list = { 'docs': [] };
                $scope.db2.rows.forEach(function (item) {
                    // set updated document status according to allow flag
                    item.doc['reviewed'] = allow ? 'accepted' : 'rejected';
                    approve_list.docs.push(item.doc);
                });
                // run bulk update
                var client = new XMLHttpRequest();
                client.open('POST', couchdb_url + '/csp/_bulk_docs');
                client.setRequestHeader('Content-Type', 'application/json');
                client.send(JSON.stringify(approve_list));
            })
            .error(function(resp) {
                $scope.error = resp;
            });

        }; // review_source

    } // function($scope
]);
