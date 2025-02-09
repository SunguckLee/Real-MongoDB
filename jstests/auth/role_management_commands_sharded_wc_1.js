(function() {
    'use strict';

    load('jstests/auth/role_management_commands_lib.js');

    var st =
        new ShardingTest({shards: 2, config: 3, keyFile: 'jstests/libs/key1', useHostname: false});
    runAllRoleManagementCommandsTests(st.s, {w: 1});
    st.stop();
})();
