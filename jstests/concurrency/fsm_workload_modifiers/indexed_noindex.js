'use strict';

/**
 * indexed_noindex.js
 *
 * Defines a modifier for indexed workloads that drops the index, specified by
 * $config.data.getIndexSpec(), at the end of the workload setup.
 */
function indexedNoindex($config, $super) {
    $config.setup = function(db, collName, cluster) {
        $super.setup.apply(this, arguments);

        var res = db[collName].dropIndex(this.getIndexSpec());
        assertAlways.commandWorked(res);
        this.indexExists = false;
    };

    // Remove the shard key for the no index tests
    delete $config.data.shardKey;

    return $config;
}
