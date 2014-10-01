/**
 * Created by pawelkrawczyk on 01/10/2014.
 */

cspControllers.controller('CspAnalysisController', ['$scope',
    function ($scope) { "use strict";

        $scope.new_csp = function () {
            var a = Math.random().toString().replace('.','');
            var b = Math.random().toString().replace('.','');
            var new_owner_id = a + b;
            new_owner_id = new_owner_id.substring(0, 19);
            var approved_list = empty_approved_list();
            var csp_config = default_csp_config();
            var format = 'generic';
            $scope.new_policy = policy_generator(new_owner_id, format, csp_config, approved_list);
        }

    }]);