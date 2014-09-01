var couchdb_url = 'http://new.cspbuilder.info:8080';

var cspbuilderApp = angular.module('cspbuilderApp', ['ngRoute', 'ngCookies', 'cspControllers']);

cspbuilderApp.config(['$routeProvider',
    function($routeProvider) {
    $routeProvider.
        when('/analysis/', {
            templateUrl: 'analysis.html',
            controller: 'CspAnalysisController'
        }).
        when('/policy/', {
            templateUrl: 'policy.html',
            controller: 'CspPolicyController'
        }
        ).
        when('/reports/', {
            templateUrl: 'reports.html',
            controller: 'CspReportsController'
        }
        ).
        when('/live/', {
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




