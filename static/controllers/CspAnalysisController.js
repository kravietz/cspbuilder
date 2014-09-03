cspControllers.controller('CspAnalysisController', ['$scope', '$cookieStore', 'cornercouch', '$window',
    function ($scope, $cookieStore, cornercouch, $window) {

        $scope.owner_id = $cookieStore.get('owner_id');
        if (!$scope.owner_id) {
            $window.location.href = '/static/#/login';
        }

        $scope.blocked = true;
        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.index = 0;
        $scope.db.query("csp", "sources_key_owner", {
            include_docs: false,
            // CouchDB idiom used to narrow search
            // ref: http://docs.couchdb.org/en/latest/couchapp/views/collation.html#string-ranges
            startkey: [parseInt($scope.owner_id)],
            endkey: [parseInt($scope.owner_id), {}],
            // group required for reduce function to work
            group: true
        })
            .success(function () {
                console.log('data loading finished');
                $scope.blocked = false;
            });

        $scope.logout = function () {
            console.log('logout');
            $cookieStore.remove('owner_id');
            $window.location.href = '/static/#/login';
        };

        $scope.detail_close = function () {
            console.log('detail_close ');
            delete $scope.meta;
            delete $scope.raw_report;
        };

        $scope.detail_open = function (index) {
            console.log('detail_open ' + index);
            $scope.reviewed = false;
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
                })
                .success(function () {
                    $scope.csp = $scope.db2.rows[0].doc['csp-report'];
                    $scope.meta = $scope.db2.rows[0].doc.meta;
                    $scope.norm_type = $scope.csp['violated-directive'].split(' ')[0];
                    $scope.norm_src = normalize_csp_source($scope.csp);
                })
                .error(function(resp) {
                    $scope.error = resp;
                });
        };   // detail_open

        $scope.review_source = function (allow) {

            console.log('review_source allow=' + allow);

            // highlight processed row according to its state
            if (allow) {
                $('#report-row-' + $scope.index).addClass('bg-success');
            } else {
                $('#report-row-' + $scope.index).addClass('bg-warning');
            }

            // save new whitelist/blacklist entry if action was to allow
            db2 = cornercouch(couchdb_url, 'GET').getDB('csp');
            newdoc = {  'owner_id': parseInt($scope.owner_id),
                        'known_uri': $scope.norm_src,
                        'known_type': $scope.norm_type,
                        'action': allow ? 'accept' : 'reject'
            };
            db2.newDoc(newdoc).save();

            // mark as approved on the page
            $scope.reviewed = true;

            // set all reports with this key as reviewed
            $scope.db2.query('csp', 'by_source_type', {
                key: [parseInt($scope.owner_id), $scope.norm_type, $scope.norm_src],
                include_docs: true
            }).success(function () {
                approve_list = { 'docs': [] };
                $scope.db2.rows.forEach(function (item) {
                    // set updated document status according to allow flag
                    item.doc['reviewed'] = allow ? 'accepted' : 'rejected';
                    approve_list.docs.push(item.doc);
                });
                // run bulk update
                client = new XMLHttpRequest();
                client.open('POST', couchdb_url + '/csp/_bulk_docs');
                client.setRequestHeader('Content-Type', 'application/json');
                client.send(JSON.stringify(approve_list));
            });

        }; // review_source

    } // function($scope
]);
