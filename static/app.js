var couchdb_url = 'http://new.cspbuilder.info:9091/';

var cspbuilderApp = angular.module('cspbuilderApp', ['ngRoute', 'cspControllers']);

cspbuilderApp.config(['$routeProvider',
    function($routeProvider) {
    $routeProvider.
        when('/analysis/:owner_id', {
            templateUrl: 'analysis.html',
            controller: 'CspAnalysisController'
        }).
        when('/policy/:owner_id', {
            templateUrl: 'policy.html',
            controller: 'CspPolicyController'
        }
        ).
        when('/reports/:owner_id', {
            templateUrl: 'reports.html',
            controller: 'CspReportsController'
        }
        ).
        when('/live/:owner_id', {
            templateUrl: 'live.html',
            controller: 'CspLiveController'
        }
        ).
        when('/login', {
            templateUrl: 'login.html',
            controller: 'CspLoginController'
        }
        ).
        otherwise({
            redirectTo: '/login'
        }
        );
    }
]);



function screenRows() {
    return Math.round(
            window.innerHeight / (
                    Math.round(
                            $('#main-list').css('font-size').replace('px','')
                        )
                )
        )
}

var cspControllers = angular.module('cspControllers', ['CornerCouch','infinite-scroll']);




