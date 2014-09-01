cspControllers.controller('CspReportsController', ['$scope', '$cookieStore', 'cornercouch', '$window',
    function($scope, $cookieStore, cornercouch, $window) {

        $scope.owner_id = $cookieStore.get('owner_id');
        if(!$scope.owner_id) { $window.location.href='/static/#/login'; }

        $scope.blocked = true; // for infinite scroll
        $('#reports-prev-button').addClass('disabled');
        $scope.index = 0;

        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.db.query("csp", "all_by_owner",
            {
                include_docs: true,
                key: Math.floor($scope.owner_id),
                limit: screenRows('#reports-left-list')
            }).success( function() {
                    console.log('data loading finished');
                    $scope.blocked = false;
                    $scope.detail_show(0);
                }
            );

        $scope.logout = function() {
            console.log('logout');
            $cookieStore.remove('owner_id');
            $window.location.href='/static/#/login';
        };

        $scope.detail_show = function(index) {
            console.log('detail_show '+index);
            $scope.index = index; // update scope index
            $scope.csp = $scope.db.rows[index].doc['csp-report'];
            $scope.meta = $scope.db.rows[index].doc['meta'];
            $scope.raw = 0;

            if($scope.index==0) {
                $('#reports-prev-button').addClass('disabled');
            } else {
                $('#reports-prev-button').removeClass('disabled');
            }
            if($scope.index==($scope.db.rows.length-1)) {
                $('#reports-next-button').addClass('disabled');
            } else {
                $('#reports-next-button').removeClass('disabled');
            }

        };

        $scope.detail_prev = function() {
            console.log('detail_prev ' + $scope.index);
            if($scope.index>0) {
                $scope.detail_show($scope.index-1);
            }
        };

        $scope.detail_next = function() {
            console.log('detail_next ' + $scope.index);
            if($scope.index<$scope.db.rows.length) {
                $scope.detail_show($scope.index+1);
            }
        };

        $scope.loadNextPage = function() {
            $scope.db.queryMore().success( function() {
                    console.log('data loading finished');
                    $scope.blocked = false;
                });
        };

         $scope.open_raw = function(index) {
            console.log('open_raw');
            $scope.show_raw = true;
            $scope.show_original = false;
            $scope.show_violated = false;
         };
         $scope.open_original = function(index) {
            $scope.show_raw = false;
            $scope.show_original = true;
            $scope.show_violated = false;
         };
         $scope.open_violated = function(index) {
            $scope.show_raw = false;
            $scope.show_original = false;
            $scope.show_violated = true;
         };


    }
]);