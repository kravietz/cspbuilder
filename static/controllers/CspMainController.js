/**
 * Created by Paweł Krawczyk on 01/10/2014.
 */

cspControllers.controller('CspMainController', ['$scope',
    function ($scope) { "use strict";

        $scope.new_csp = function (format) {
            var a = Math.random().toString().replace('.', '').substr(0, 15);
            var b = Math.random().toString().replace('.', '').substr(0, 15);
            var new_owner_id = a + b;
            new_owner_id = new_owner_id.substring(1, 19); // skip leading 0
            var approved_list = empty_approved_list();
            var csp_config = default_csp_config();
            var policy = generate_csp(new_owner_id, format, csp_config, approved_list);
            $scope.new_policy = policy[0];
            $scope.new_owner_id = new_owner_id;

            mixpanel.track("Get code");
        }

    }]);