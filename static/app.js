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

function normalize_csp_source(csp) {
    blocked_uri = csp['blocked-uri'];
    blocked_type = csp['violated-directive'].split(' ')[0];

    // for 'data:image/png' return 'data:'
    if(blocked_uri.lastIndexOf('data', 0) === 0) {
        blocked_uri='\'data:\'';

    // for 'http://url.com/path/path' return 'http://url.com'
    } else if(/^https?:\/\/[a-zA-Z0-9.:-]+/.test(blocked_uri)) {
        blocked_uri=blocked_uri.match(/^(https?:\/\/[a-zA-Z0-9.:-]+)/)[1];

    // 'self' is easy
    } else if(blocked_uri === 'self') {
        blocked_uri='\'self\'';

    // empty URI can be inline or eval()
    } else if(blocked_uri === 'null') {

        // if type was style, then inline CSS was blocked
        if(blocked_type === 'style-src') {
            blocked_uri='\'unsafe-inline\'';

        // guesswork needed for scripts
        } else if (blocked_type === 'script-src') {

            violated_direcive = csp['violated-directive'];

            // check if eval was already allowed on blocked page
            if(violated_directive.indexIf('unsafe-eval') > 0) {
                // so the blocked resource was an inline script
                blocked_uri='\'unsafe-inline\'';
            } else {
                // otherwise it must have been eval()
                blocked_uri='\'unsafe-eval\'';
            }

        }
    }
    return blocked_uri;
}

var cspControllers = angular.module('cspControllers', ['CornerCouch','infinite-scroll']);




