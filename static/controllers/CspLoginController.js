cspControllers.controller('CspLoginController', ['$scope', 'cornercouch',
    function($scope, cornercouch) {
            console.log('CspLoginCtrl');
            $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
    }
]);