/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

cspControllers.controller('CspPolicyController', ['$scope', 'cornercouch', '$rootScope', '$sce',
    function ($scope, cornercouch, $rootScope, $sce) {
        "use strict";

        console.log('CspPolicyController owner_id=' + $rootScope.owner_id);

        $scope.csp_config = {
            'enforce': false,
            'default': false,
            'referrer': 'origin-when-cross-origin',
            'reflected_xss': 'filter',
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

                // the initial list needs to include all content types
                // so that the output policy contains proper 'none' entries
                // and browsers do not need to fall back to default-src
                $scope.approved_list = empty_approved_list();

                // rewrite the list of accepted items into a dictionary
                $scope.db.rows.forEach(function (item) {
                    // {"id":"00b68742da0e40848f0982f95dfdf8dc","key":"9018643792216450862","value":["script-src","about","reject",null]},
                    var type = item.value[0];
                    var src = item.value[1];
                    var action = item.value[2];

                    // only items with 'accept' action go into the CSP
                    if (action == 'accept') {
                        /*
                         Output from this loop:
                         {
                         'script-src' : {'source1':true, 'source2':true },
                         'style-src' : {'source3':true, 'source4':true }
                         }
                         */

                        // add the known source to approved list
                        $scope.approved_list[type][src] = true;

                        // delete the default 'none' entry
                        delete $scope.approved_list[type]["'none'"];
                    }

                });

                // finally generate the generic CSP on the page
                $scope.generate_csp();

            }
        );

        mixpanel.track("View policy");

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

            if (format == 'ror') {
                var result = ror_generator($rootScope.owner_id, $scope.csp_config, $scope.approved_list);
            } else {
                var result = policy_generator($rootScope.owner_id, format, $scope.csp_config, $scope.approved_list);
            }

            $scope.policy = result[0];
            $scope.policy_message = $sce.trustAsHtml(result[1]);

            mixpanel.track("Generate policy " + format);

        };

    }
]);