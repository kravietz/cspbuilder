/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

cspControllers.controller('CspPolicyController', ['$scope', 'cornercouch', '$rootScope',
    function ($scope, cornercouch, $rootScope) { "use strict";

        console.log('CspPolicyController owner_id=' + $rootScope.owner_id);

        $scope.csp_config = {
            'enforce': false,
            'default': false,
            'referrer': 'none',
            'reflected_xss': 'block',
            'header_format': 'standard',
            'plugin_types': [
                'application/pdf',
                'application/x-shockwave-flash',
                'application/java'
            ],
            'plugin_choice': []
        };

        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.db.query("csp", "1000_known_list", { key: $rootScope.owner_id })
            .success(function () {
                console.log('data loading finished');
                $scope.approved_list = [];
                var current_type = null;
                var current_list = {};
                // rewrite the list of accepted items into a dictionary
                $scope.db.rows.forEach(function (item) {
                    // {"id":"00b68742da0e40848f0982f95dfdf8dc","key":"9018643792216450862","value":["script-src","about","reject",null]},
                    var type = item.value[0];
                    var src = item.value[1];
                    var action = item.value[2];

                    if (action == 'accept') {

                        if (current_type == type) {
                            // item inside one type - add to "sources" dictionary
                            current_list[src] = true;
                        } else {
                            // new type - open new dictionary
                            if (current_type && current_list) { // save items added previously
                                $scope.approved_list.push({
                                    'type': current_type,
                                    'sources': current_list
                                });
                            }
                            current_type = type;
                            current_list = {};
                            // by default all sources are checked - the list is built
                            // from items accepted by user in Analysis tab
                            current_list[src] = true;
                        }
                    }

                });
                if(current_type && current_list) {
                    // save items added as last, intentionally stays outside of the forEach loop
                    $scope.approved_list.push({
                        'type': current_type,
                        'sources': current_list
                    });
                }
                // finally generate the generic CSP on the page
                $scope.generate_csp();

            }
        );

        // Cycle between default (empty) policy and original, generated policy array
        $scope.default_policy = function () {
            // check if we're not cycling back from default policy
            if ($scope.approved_list_backup) {
                $scope.approved_list = $scope.approved_list_backup;
                delete $scope.approved_list_backup;
                return
            }
            $scope.approved_list_backup = $scope.approved_list;
            $scope.approved_list = empty_approved_list();
        };

        $scope.generate_csp = function (format) {

            var result = policy_generator($rootScope.owner_id, format, $scope.csp_config, $scope.approved_list);
            $scope.policy = result[0];
            $scope.policy_message = result[1];

        };

    }
]);