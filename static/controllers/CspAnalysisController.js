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



        $scope.detail_close = function() {
            console.log('detail_close ');
            delete $scope.meta;
            delete $scope.raw_report;
        };



]);
