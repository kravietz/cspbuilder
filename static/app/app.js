/**
 * Created by Paweł Krawczyk on 04/09/2014.
 */

"use strict";

var couchdb_url = '';

var cspbuilderApp = angular.module('cspbuilderApp', ['ngRoute', 'ngCookies', 'cspControllers']);

cspbuilderApp.config(['$routeProvider',
    function ($routeProvider) {
        $routeProvider.
            when('/main/', {
                templateUrl: '/static/main.html',
                controller: 'CspMainController',
                activeTab: 'main'

            }).
            when('/analysis/', {
                templateUrl: '/static/analysis.html',
                controller: 'CspAnalysisController',
                activeTab: 'analysis'
            }).
            when('/policy/', {
                templateUrl: '/static/policy.html',
                controller: 'CspPolicyController',
                activeTab: 'policy'
            }
        ).
            when('/reports/', {
                templateUrl: '/static/reports.html',
                controller: 'CspReportsController',
                activeTab: 'reports'
            }
        ).
            when('/live/', {
                templateUrl: '/static/live.html',
                controller: 'CspLiveController',
                activeTab: 'live'
            }
        ).
            when('/known/', {
                templateUrl: '/static/known.html',
                controller: 'CspKnownController',
                activeTab: 'known'
            }
        ).
            when('/feedback', {
                templateUrl: '/static/feedback.html',
                activeTab: 'feedback'
            }
        ).
            when('/faq', {
                templateUrl: '/static/faq.html',
                activeTab: 'faq'
            }
        ).
            otherwise({
                redirectTo: '/main'
            }
        );
    }
]);


// determine browser window height in rows
function screen_rows(obj) {
    var font_size = Math.floor($(obj).css('font-size').replace('px', ''));
    return Math.floor(window.innerHeight / font_size / 1.8);
}

// return CouchDB database name for specific owner_id
// needs to stay in sync with api/utils.py
function get_db_for_user(owner_id) {
    return "reports_" + owner_id;
}

var cspControllers = angular.module('cspControllers', ['CornerCouch', 'ui.bootstrap']);




