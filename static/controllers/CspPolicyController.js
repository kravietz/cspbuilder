cspControllers.controller('CspPolicyController', ['$scope', '$cookieStore', 'cornercouch', '$window',
    function ($scope, $cookieStore, cornercouch, $window) {

        $scope.csp_config = {
            'enforce': false,
            'default': false,
            'referrer': 'none',
            'reflected_xss': 'block',
            'header_format': 'standard'
        };

        $scope.owner_id = $cookieStore.get('owner_id');
        if (!$scope.owner_id) {
            $window.location.href = '/static/#/login';
        }

        $scope.db = cornercouch(couchdb_url, 'GET').getDB('csp');
        $scope.db.query("csp", "approved_sources_owner",
            {
                startkey: [parseInt($scope.owner_id)],
                endkey: [parseInt($scope.owner_id), {}],
                group: true
            }).success(function () {
                console.log('data loading finished');
                $scope.approved_list = [];
                var current_type = null;
                var current_list = {};
                // rewrite the list of accepted items into a dictionary
                $scope.db.rows.forEach(function (item) {
                    console.log('row=' + item);
                    var type = item.key[1];
                    var src = item.key[2];
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

                });
                $scope.approved_list.push({ // save last added items
                    'type': current_type,
                    'sources': current_list
                });

            }
        );

        $scope.logout = function () {
            console.log('logout');
            $cookieStore.remove('owner_id');
            $window.location.href = '/static/#/login';
        };

        // TODO: add various types from https://www.owasp.org/index.php/Content_Security_Policy
        // https://w3c.github.io/webappsec/specs/content-security-policy/#csp-request-header
        function ror_generator() {
            // TODO: https://github.com/twitter/secureheaders
            return null;
        }
        function django_generator() {
            // TODO: https://github.com/kravietz/django-security
            return null;
        }

        // Cycle between default (empty) policy and original, generated policy array
        $scope.default_policy = function() {
            // check if we're not cycling back from default policy
            if($scope.approved_list_backup) {
                $scope.approved_list = $scope.approved_list_backup;
                delete $scope.approved_list_backup;
                return
            }
             $scope.approved_list_backup = $scope.approved_list;
             $scope.approved_list = [];
            // report-uri and default-src will be added automatically
            var types = ['connect-src','child-src','font-src','form-action','frame-ancestors','frame-src',
                        'img-src','media-src','object-src','script-src','style-src'];
            types.forEach( function (type) {
                $scope.approved_list.push(
                    {'type':type, 'sources': {'\'none\'':true}}
                );
            });
        };

        $scope.generate_csp = function (format) {

            // select CSP header format
            switch($scope.csp_config.header_format) {
                case 'xcsp':
                    var header = 'X-Content-Security-Policy';
                    break;
                case 'webkit':
                    var header = 'X-WebKit-CSP';
                    break;
                default:
                    var header = 'Content-Security-Policy';
            }

            // append RO if enforcenement is not selected
            if (!$scope.csp_config.enforce) {
                header += '-Report-Only';
            }

            var policy = 'report-uri http://new.cspbuilder.info:8080/report/' + $scope.owner_id + '; ';

            for (var i = 0; i < $scope.approved_list.length; i++) {
                var src_list = $scope.approved_list[i];
                policy += src_list.type + ' ';
                var sources = Object.keys(src_list.sources);
                for(var j=0; j<sources.length; j++) {
                    if(src_list.sources[sources[j]]) {
                        policy += ' ' + sources[j];
                    }
                }
                policy += '; ';
            }

            // add default source
            policy += 'default-src \'none\';';

            // produce final formatted output depending on requested format
            switch(format) {
                case 'nginx':
                    $scope.policy = 'add_header ' + header + ' "' + policy + '";';
                    break;
                case 'apache':
                    $scope.policy = 'Header set ' + header + ' "' + policy + '"';
                    break;
                case 'php':
                    $scope.policy = 'header("' + header + ': ' + policy + '");';
                    break;
                case 'ror':
                    $scope.policy_message = 'Use <a href="https://github.com/twitter/secureheaders">secureheaders</a>.';
                    $scope.policy = ror_generator();
                    break;
                case 'django':
                    $scope.policy_message = 'Use <a href="https://github.com/kravietz/django-security">django-security</a>.';
                    $scope.policy = django_generator();
                default:
                    $scope.policy = header + ': ' + policy;
            }

        };

    }
]);