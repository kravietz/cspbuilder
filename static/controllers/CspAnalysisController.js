cspControllers.controller('CspAnalysisController', ['$scope', '$routeParams', 'cornercouch',
    function($scope, $routeParams, cornercouch) {

        $scope.owner_id = $routeParams.owner_id;
        $scope.blocked = true;
        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.db.query("csp", "sources_key_owner",
            {
                include_docs: false,
                // CouchDB idiom used to narrow search
                // ref: http://docs.couchdb.org/en/latest/couchapp/views/collation.html#string-ranges
                startkey: [Math.floor($scope.owner_id)],
                endkey: [Math.floor($scope.owner_id),{}],
                // group required for reduce function to work
                group: true
            }).success( function() {
                    console.log('data loading finished');
                    $scope.blocked = false;
                }
            );

        $scope.detail_open = function(index) {
            console.log('detail_open '+index);
            $scope.approved = false;
            // sources list already contains the key we can use to fetch sample report
            console.log($scope.db.rows[index].key);
            $scope.db2 = cornercouch(couchdb_url, 'GET').getDB('csp');
            $scope.db2.query('csp', 'by_source_type',
            {
                limit: 1,
                startkey: $scope.db.rows[index].key,
                include_docs: true
            }).success( function() {
                console.log('sample data loading finished');
                console.log($scope.db2.rows[0].doc['csp-report']);
                $scope.csp = $scope.db2.rows[0].doc['csp-report'];
                $scope.meta = $scope.db2.rows[0].doc.meta;
            }
            );

        };

        $scope.detail_close = function() {
            console.log('detail_close ');
            delete $scope.meta;
            delete $scope.raw_report;
        }

        $scope.approve_source = function() {
                db2 = cornercouch(couchdb_url, 'GET').getDB('csp');
                newdoc = {  'owner_id': $scope.owner_id,
                            'approved_uri' : $scope.csp['blocked-uri'],
                            'approved_type': $scope.csp['violated-directive'].split(' ')[0]
                            };
                db2.newDoc(newdoc).save();
                $scope.approved = true;

        };

    }
]);