cspControllers.controller('CspLoginController', ['$scope', 'cornercouch', '$cookieStore',
    function ($scope, cornercouch, $cookieStore) {
        console.log('CspLoginCtrl');
        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');

        $scope.cookieStore = $cookieStore;

        $scope.login = function () {
            console.log('login owner_id' + $scope.owner_id);
            $scope.cookieStore.put('owner_id', $scope.owner_id);
            window.location.href = '/static/#/analysis';
        };
    }
]);