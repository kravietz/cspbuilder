/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

"use strict";

// check if user is logged in
$scope.owner_id = $cookieStore.get('owner_id');
if (!$scope.owner_id) {
    $window.location.href = '/static/#/login';
}

var couchdb_url = 'http://new.cspbuilder.info:8080';

var cspbuilderApp = angular.module('cspbuilderApp', ['ngRoute', 'ngCookies', 'cspControllers']);

cspbuilderApp.config(['$routeProvider',
    function ($routeProvider) {
        $routeProvider.
            when('/analysis/', {
                templateUrl: '/static/analysis.html',
                controller: 'CspAnalysisController'
            }).
            when('/policy/', {
                templateUrl: '/static/policy.html',
                controller: 'CspPolicyController'
            }
        ).
            when('/reports/', {
                templateUrl: '/static/reports.html',
                controller: 'CspReportsController'
            }
        ).
            when('/live/', {
                templateUrl: '/static/live.html',
                controller: 'CspLiveController'
            }
        ).
            when('/known/', {
                templateUrl: '/static/known.html',
                controller: 'CspKnownController'
            }
        ).
            when('/login', {
                templateUrl: '/static/login.html',
                controller: 'CspLoginController'
            }
        ).
            otherwise({
                redirectTo: '/login'
            }
        );
    }
]);


// determine browser window height in rows
function screen_rows(obj) {
    var font_size = Math.floor($(obj).css('font-size').replace('px', ''));
    return Math.floor(window.innerHeight / font_size / 1.8);
}

var cspControllers = angular.module('cspControllers', ['CornerCouch']);




