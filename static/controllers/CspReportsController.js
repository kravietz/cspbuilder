cspControllers.controller('CspReportsController', ['$scope', '$cookieStore', 'cornercouch', '$window',
    function ($scope, $cookieStore, cornercouch, $window) {

        $scope.owner_id = $cookieStore.get('owner_id');
        if (!$scope.owner_id) {
            $window.location.href = '/static/#/login';
        }

        $scope.blocked = true; // for infinite scroll
        $('#reports-prev-button').addClass('disabled');
        $scope.index = 0;

        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.db.query("csp", "all_by_owner",
            {
                include_docs: true,
                key: Math.floor($scope.owner_id),
                limit: screenRows('#reports-left-list')
            })
            .success(function () {
                console.log('data loading finished');
                $scope.blocked = false;
                $scope.detail_show(0);
            })
            .error(function(resp) {
                $scope.blocked = false;
                $scope.error = resp;
            });

        $scope.logout = function () {
            console.log('logout');
            $cookieStore.remove('owner_id');
            $window.location.href = '/static/#/login';
        };

        $scope.detail_show = function (index) {
            console.log('detail_show ' + index);
            $('#reports-li-' + $scope.index).removeClass('bg-info'); // remove highlight from previous
            $scope.index = index; // update scope index
            $('#reports-li-' + $scope.index).addClass('bg-info'); // highlight

            $scope.csp = $scope.db.rows[index].doc['csp-report'];
            $scope.meta = $scope.db.rows[index].doc['meta'];
            $scope.raw = 0;

            if ($scope.index == 0) {
                $('#reports-prev-button').addClass('disabled');
            } else {
                $('#reports-prev-button').removeClass('disabled');
            }
            if ($scope.index == ($scope.db.rows.length - 1)) {
                $('#reports-next-button').addClass('disabled');
            } else {
                $('#reports-next-button').removeClass('disabled');
            }

        };

        $scope.detail_prev = function () {
            console.log('detail_prev ' + $scope.index);
            if ($scope.index > 0) {
                $scope.detail_show($scope.index - 1);
            }
        };

        $scope.detail_next = function () {
            console.log('detail_next ' + $scope.index);
            if ($scope.index < $scope.db.rows.length) {
                $scope.detail_show($scope.index + 1);
            }
        };

        $scope.load_next_page = function () {
            console.log('load next page');
            $scope.db.queryMore().success(function () {
                console.log('data loading finished');
                $scope.blocked = false;
            });
        };

        $scope.open_raw = function (index) {
            console.log('open_raw');
            $scope.show_raw = true;
            $scope.show_original = false;
            $scope.show_violated = false;
        };
        $scope.open_original = function (index) {
            $scope.show_raw = false;
            $scope.show_original = true;
            $scope.show_violated = false;
        };
        $scope.open_violated = function (index) {
            $scope.show_raw = false;
            $scope.show_original = false;
            $scope.show_violated = true;
        };

        $scope.delete_all = function () {

            if(!confirm('Are you sure?')) { return }

            $scope.db2 = cornercouch(couchdb_url, 'GET').getDB('csp');
            $scope.db2.query('csp', 'all_by_owner', {
                key: Math.floor($scope.owner_id),
                include_docs: true
            })
                .success(function () {
                    delete_list = { 'docs': [] };
                    $scope.db2.rows.forEach(function (item) {
                        delete_list.docs.push({
                            // no need to copy the whole document body on delete
                            '_id': item.doc._id,
                            '_rev': item.doc._rev,
                            '_deleted': true // this is the actual delete command
                        });
                    });
                    // run bulk delete - CornerCouch does not support it
                    client = new XMLHttpRequest();
                    client.open('POST', couchdb_url + '/csp/_bulk_docs');
                    client.setRequestHeader('Content-Type', 'application/json');
                    client.send(JSON.stringify(delete_list));
                    location.reload();
                });
        };


    }
]);