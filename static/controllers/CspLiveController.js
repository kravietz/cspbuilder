/**
 * Created by pawelkrawczyk on 08/10/2014.
 */

/**
 * Created by pawelkrawczyk on 04/09/2014.
 */

cspControllers.controller('CspLiveController', ['$scope', '$rootScope',
    function ($scope, $rootScope) {
        "use strict";

        console.log('CspLiveController owner_id=' + $rootScope.owner_id);
        mixpanel.track("View live");

        var ws = new WebSocket(couchdb_url + "/csp/_changes?feed=continuous&filter=csp/owner&owner_id=" + $rootScope.owner_id);

        ws.onopen = function () {
            console.log("Socket has been opened!");
        };

        ws.onmessage = function (message) {
            console.log('onmessage:', message);
            listener(message.data);
        };

        function listener(data) {
            var messageObj = data;
            console.log("listener: ", messageObj);
            $scope.report = data;
        };

    }
]);