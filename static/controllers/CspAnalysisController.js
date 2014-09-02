cspControllers.controller('CspAnalysisController', ['$scope', '$cookieStore', 'cornercouch', '$window',
    function($scope, $cookieStore, cornercouch, $window) {

        $scope.owner_id = $cookieStore.get('owner_id');
        if(!$scope.owner_id) { $window.location.href='/static/#/login'; }

        $scope.blocked = true;
        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.index = 0;
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

        $scope.logout = function() {
            console.log('logout');
            $cookieStore.remove('owner_id');
            $window.location.href='/static/#/login';
        };

        $scope.detail_open = function(index) {
            console.log('detail_open '+index);
            $scope.approved = false;
            $('#report-row-' + $scope.index).removeClass('bg-info'); // delete highlight from old row
            $scope.index = index;
            $('#report-row-' + $scope.index).addClass('bg-info'); // highlight current row
            // sources list already contains the key we can use to fetch sample report
            $scope.db2 = cornercouch(couchdb_url, 'GET').getDB('csp');
            $scope.db2.query('csp', 'by_source_type',
            {
                limit: 1,
                startkey: $scope.db.rows[index].key, // endkey not needed because limit=1
                include_docs: true
            }).success( function() {
                $scope.csp = $scope.db2.rows[0].doc['csp-report'];
                $scope.meta = $scope.db2.rows[0].doc.meta;
                $scope.norm_type = $scope.csp['violated-directive'].split(' ')[0];
                $scope.norm_src = normalize_csp_source($scope.csp);
            }
            );

        };

         $scope.reset_approved = function() {
             $scope.db2 = cornercouch(couchdb_url, 'GET').getDB('csp');
             $scope.db2.query('csp', 'approved_sources_owner', {
                reduce: false,
                startkey: [$scope.owner_id],
                endkey: [$scope.owner_id,{}],
                include_docs: true
                    }).success( function() {
                    delete_list = { 'docs': [] }
                $scope.db2.rows.forEach( function(item) {
                    delete_list.docs.push({
                        '_id': item.doc._id,
                        '_rev': item.doc._rev,
                        '_deleted' : true
                    });
                });
                // run bulk delete - CornerCouch does not support it
                client = new XMLHttpRequest();
                client.open('POST', couchdb_url + '/csp/_bulk_docs');
                client.setRequestHeader('Content-Type', 'application/json');
                client.send(JSON.stringify(delete_list));
                }
            );
         };

        $scope.detail_close = function() {
            console.log('detail_close ');
            delete $scope.meta;
            delete $scope.raw_report;
        };

        $scope.approve_source = function() {

                console.log('approve_source');
                db2 = cornercouch(couchdb_url, 'GET').getDB('csp');
                newdoc = {  'owner_id'     : $scope.owner_id,
                            'approved_uri' : $scope.norm_src,
                            'approved_type': $scope.norm_type
                            };
                db2.newDoc(newdoc).save();
                $scope.approved = true;

                 // set all reports with this key as approved
                 $scope.db2.query('csp', 'by_source_type', {
                        key: [$scope.owner_id, $scope.norm_type, $scope.norm_src],
                        include_docs: true
                    }).success( function() {
                        approve_list = { 'docs': [] }
                        $scope.db2.rows.forEach( function(item) {
                            approve_list.docs.push({
                                '_id': item.doc._id,
                                '_rev': item.doc._rev,
                                'approved' : true
                            });
                            console.log('set as approved ' + $scope.db2.length);
                        });
                        // run bulk update
                        client = new XMLHttpRequest();
                        client.open('POST', couchdb_url + '/csp/_bulk_docs');
                        client.setRequestHeader('Content-Type', 'application/json');
                        client.send(JSON.stringify(approve_list));
                    });

        };
]);
