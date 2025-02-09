/*
 * DO NOT EDIT: automatically built by dist/flags.py.
 * flags section: BEGIN
 */
#define	WT_CHECKPOINTING				0x00000001
#define	WT_CONN_CACHE_POOL				0x00000001
#define	WT_CONN_CKPT_SYNC				0x00000002
#define	WT_CONN_CLOSING					0x00000004
#define	WT_CONN_CLOSING_NO_MORE_OPENS			0x00000008
#define	WT_CONN_EVICTION_RUN				0x00000010
#define	WT_CONN_IN_MEMORY				0x00000020
#define	WT_CONN_LAS_OPEN				0x00000040
#define	WT_CONN_LEAK_MEMORY				0x00000080
#define	WT_CONN_LSM_MERGE				0x00000100
#define	WT_CONN_PANIC					0x00000200
#define	WT_CONN_READONLY				0x00000400
#define	WT_CONN_RECOVERING				0x00000800
#define	WT_CONN_SERVER_ASYNC				0x00001000
#define	WT_CONN_SERVER_CHECKPOINT			0x00002000
#define	WT_CONN_SERVER_LOG				0x00004000
#define	WT_CONN_SERVER_LSM				0x00008000
#define	WT_CONN_SERVER_STATISTICS			0x00010000
#define	WT_CONN_SERVER_SWEEP				0x00020000
#define	WT_CONN_WAS_BACKUP				0x00040000
#define	WT_EVICTING					0x00000002
#define	WT_EVICT_INMEM_SPLIT				0x00000004
#define	WT_EVICT_IN_MEMORY				0x00000008
#define	WT_EVICT_LOOKASIDE				0x00000010
#define	WT_EVICT_SCRUB					0x00000020
#define	WT_EVICT_UPDATE_RESTORE				0x00000040
#define	WT_LOGSCAN_FIRST				0x00000001
#define	WT_LOGSCAN_FROM_CKP				0x00000002
#define	WT_LOGSCAN_ONE					0x00000004
#define	WT_LOGSCAN_RECOVER				0x00000008
#define	WT_LOG_BACKGROUND				0x00000001
#define	WT_LOG_DSYNC					0x00000002
#define	WT_LOG_FLUSH					0x00000004
#define	WT_LOG_FSYNC					0x00000008
#define	WT_LOG_SYNC_ENABLED				0x00000010
#define	WT_READ_CACHE					0x00000001
#define	WT_READ_COMPACT					0x00000002
#define	WT_READ_NOTFOUND_OK				0x00000004
#define	WT_READ_NO_EMPTY				0x00000008
#define	WT_READ_NO_EVICT				0x00000010
#define	WT_READ_NO_GEN					0x00000020
#define	WT_READ_NO_WAIT					0x00000040
#define	WT_READ_PREV					0x00000080
#define	WT_READ_RESTART_OK				0x00000100
#define	WT_READ_SKIP_INTL				0x00000200
#define	WT_READ_SKIP_LEAF				0x00000400
#define	WT_READ_TRUNCATE				0x00000800
#define	WT_READ_WONT_NEED				0x00001000
#define	WT_SESSION_CAN_WAIT				0x00000001
#define	WT_SESSION_INTERNAL				0x00000002
#define	WT_SESSION_LOCKED_CHECKPOINT			0x00000004
#define	WT_SESSION_LOCKED_HANDLE_LIST_READ		0x00000008
#define	WT_SESSION_LOCKED_HANDLE_LIST_WRITE		0x00000010
#define	WT_SESSION_LOCKED_METADATA			0x00000020
#define	WT_SESSION_LOCKED_PASS				0x00000040
#define	WT_SESSION_LOCKED_SCHEMA			0x00000080
#define	WT_SESSION_LOCKED_SLOT				0x00000100
#define	WT_SESSION_LOCKED_TABLE_READ			0x00000200
#define	WT_SESSION_LOCKED_TABLE_WRITE			0x00000400
#define	WT_SESSION_LOCKED_TURTLE			0x00000800
#define	WT_SESSION_LOGGING_INMEM			0x00001000
#define	WT_SESSION_LOOKASIDE_CURSOR			0x00002000
#define	WT_SESSION_NO_CACHE				0x00004000
#define	WT_SESSION_NO_DATA_HANDLES			0x00008000
#define	WT_SESSION_NO_EVICTION				0x00010000
#define	WT_SESSION_NO_LOGGING				0x00020000
#define	WT_SESSION_NO_SCHEMA_LOCK			0x00040000
#define	WT_SESSION_QUIET_CORRUPT_FILE			0x00080000
#define	WT_SESSION_SERVER_ASYNC				0x00100000
#define	WT_STAT_CLEAR					0x00000001
#define	WT_STAT_JSON					0x00000002
#define	WT_STAT_ON_CLOSE				0x00000004
#define	WT_STAT_TYPE_ALL				0x00000008
#define	WT_STAT_TYPE_CACHE_WALK				0x00000010
#define	WT_STAT_TYPE_FAST				0x00000020
#define	WT_STAT_TYPE_SIZE				0x00000040
#define	WT_STAT_TYPE_TREE_WALK				0x00000080
#define	WT_TXN_LOG_CKPT_CLEANUP				0x00000001
#define	WT_TXN_LOG_CKPT_PREPARE				0x00000002
#define	WT_TXN_LOG_CKPT_START				0x00000004
#define	WT_TXN_LOG_CKPT_STOP				0x00000008
#define	WT_TXN_LOG_CKPT_SYNC				0x00000010
#define	WT_TXN_OLDEST_STRICT				0x00000001
#define	WT_TXN_OLDEST_WAIT				0x00000002
#define	WT_VERB_API					0x00000001
#define	WT_VERB_BLOCK					0x00000002
#define	WT_VERB_CHECKPOINT				0x00000004
#define	WT_VERB_COMPACT					0x00000008
#define	WT_VERB_EVICT					0x00000010
#define	WT_VERB_EVICTSERVER				0x00000020
#define	WT_VERB_EVICT_STUCK				0x00000040
#define	WT_VERB_FILEOPS					0x00000080
#define	WT_VERB_HANDLEOPS				0x00000100
#define	WT_VERB_LOG					0x00000200
#define	WT_VERB_LSM					0x00000400
#define	WT_VERB_LSM_MANAGER				0x00000800
#define	WT_VERB_METADATA				0x00001000
#define	WT_VERB_MUTEX					0x00002000
#define	WT_VERB_OVERFLOW				0x00004000
#define	WT_VERB_READ					0x00008000
#define	WT_VERB_REBALANCE				0x00010000
#define	WT_VERB_RECONCILE				0x00020000
#define	WT_VERB_RECOVERY				0x00040000
#define	WT_VERB_RECOVERY_PROGRESS			0x00080000
#define	WT_VERB_SALVAGE					0x00100000
#define	WT_VERB_SHARED_CACHE				0x00200000
#define	WT_VERB_SPLIT					0x00400000
#define	WT_VERB_TEMPORARY				0x00800000
#define	WT_VERB_THREAD_GROUP				0x01000000
#define	WT_VERB_TRANSACTION				0x02000000
#define	WT_VERB_VERIFY					0x04000000
#define	WT_VERB_VERSION					0x08000000
#define	WT_VERB_WRITE					0x10000000
#define	WT_VISIBILITY_ERR				0x00000080
/*
 * flags section: END
 * DO NOT EDIT: automatically built by dist/flags.py.
 */
