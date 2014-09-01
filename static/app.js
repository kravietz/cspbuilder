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



function screenRows(obj) {
    return Math.round(
            window.innerHeight / (
                    Math.round(
                            $(obj).css('font-size').replace('px','')
                        )
                )
        )
}

function normalize_csp_source(blocked_uri) {
    // for 'data:image/png' return 'data:'
    if(blocked_uri.lastIndexOf('data', 0) === 0) {
        blocked_uri='data:';
    // for 'http://url.com/path/path' return 'http://url.com'
    } else if(/^https?:\/\/[a-zA-Z0-9.:-]+/.test(blocked_uri)) {
        blocked_uri=blocked_uri.match(/^(https?:\/\/[a-zA-Z0-9.:-]+)/)[1];
    }
    return blocked_uri;
}

var cspControllers = angular.module('cspControllers', ['CornerCouch','infinite-scroll']);




