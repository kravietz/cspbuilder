"use strict";

var couchdb_url = 'http://new.cspbuilder.info:8080';

var cspbuilderApp = angular.module('cspbuilderApp', ['ngRoute', 'ngCookies', 'cspControllers']);

cspbuilderApp.config(['$routeProvider',
    function ($routeProvider) {
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


function screen_rows(obj) {
    var font_size = Math.floor($(obj).css('font-size').replace('px', ''));
    return Math.floor(window.innerHeight / font_size / 1.6);
}

function normalize_csp_source(csp) {
    var blocked_uri = csp['blocked-uri'];
    var blocked_type = csp['violated-directive'].split(' ')[0];

    // for 'data:image/png' return 'data:'
    if (blocked_uri.lastIndexOf('data', 0) === 0) {
        blocked_uri = 'data:';

        // for 'http://url.com/path/path' return 'http://url.com'
    } else if (/^https?:\/\/[a-zA-Z0-9.:-]+/.test(blocked_uri)) {
        blocked_uri = blocked_uri.match(/^(https?:\/\/[a-zA-Z0-9.:-]+)/)[1];

        // 'self' is easy
    } else if (blocked_uri === 'self') {
        blocked_uri = '\'self\'';

        // encode empty source ("") as "null" in database, otherwise key lookups won't work
    } else if (blocked_uri.length === 0) {
        blocked_uri = 'null';

        // empty URI can be inline or eval()
    }

    // distinguishing between unsafe-inline and unsafe-eval is a guess work...
    if (blocked_uri === 'null') {

        var violated_directive = csp['violated-directive'];

        if (blocked_type === 'style-src') {

            // check if inline was already allowed on blocked page
            if (violated_directive.indexOf('unsafe-inline') > 0) {
                // otherwise it must have been eval()
                blocked_uri = '\'unsafe-eval\'';
            } else {
                // so the blocked resource was an inline script
                blocked_uri = '\'unsafe-inline\'';
            }

            // guesswork needed for scripts
        } else if (blocked_type === 'script-src') {

            // the same heuristics is used for script-src
            if (violated_directive.indexOf('unsafe-inline') > 0) {
                blocked_uri = '\'unsafe-eval\'';
            } else {
                blocked_uri = '\'unsafe-inline\'';
            }

        } else {
            console.warn('Unrecognized \'null\' source for type ' + blocked_type + ' in:' + JSON.stringify(csp));
        }
    }
    return blocked_uri;
}

var cspControllers = angular.module('cspControllers', ['CornerCouch', 'infinite-scroll']);




