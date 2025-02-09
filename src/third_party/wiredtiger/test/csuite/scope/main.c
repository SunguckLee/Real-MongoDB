/*-
 * Public Domain 2014-2016 MongoDB, Inc.
 * Public Domain 2008-2014 WiredTiger, Inc.
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include "test_util.h"

#define	KEY	"key"
#define	VALUE	"value"

static int ignore_errors;

static int
handle_error(WT_EVENT_HANDLER *handler,
    WT_SESSION *session, int error, const char *message)
{
	(void)(handler);

	/* Skip the error messages we're expecting to see. */
	if (ignore_errors > 0 &&
	    (strstr(message, "requires key be set") != NULL ||
	    strstr(message, "requires value be set") != NULL)) {
		--ignore_errors;
		return (0);
	}

	(void)fprintf(stderr, "%s: %s\n",
	    message, session->strerror(session, error));
	return (0);
}

static WT_EVENT_HANDLER event_handler = {
	handle_error,
	NULL,
	NULL,
	NULL
};

static void
cursor_scope_ops(WT_SESSION *session, const char *uri)
{
	struct {
		const char *op;
		enum { INSERT, SEARCH, SEARCH_NEAR,
		    REMOVE, REMOVE_POS, RESERVE, UPDATE } func;
		const char *config;
	} *op, ops[] = {
		/*
		 * The ops order is fixed and shouldn't change, that is, insert
		 * has to happen first so search, update and remove operations
		 * are possible, and remove has to be last.
		 */
		{ "insert", INSERT, NULL, },
		{ "search", SEARCH, NULL, },
		{ "search", SEARCH_NEAR, NULL, },
#if 0
		{ "reserve", RESERVE, NULL, },
#endif
		{ "update", UPDATE, NULL, },
		{ "remove", REMOVE, NULL, },
		{ "remove", REMOVE_POS, NULL, },
		{ NULL, INSERT, NULL }
	};
	WT_CURSOR *cursor;
	uint64_t keyr;
	const char *key, *value;
	char keybuf[100], valuebuf[100];
	int exact;
	bool recno;

	/* Reserve requires a running transaction. */
	testutil_check(session->begin_transaction(session, NULL));

	cursor = NULL;
	for (op = ops; op->op != NULL; op++) {
		key = value = NULL;

		/* Open a cursor. */
		if (cursor != NULL)
			testutil_check(cursor->close(cursor));
		testutil_check(session->open_cursor(
		    session, uri, NULL, op->config, &cursor));
		recno = strcmp(cursor->key_format, "r") == 0;

		/*
		 * Set up application buffers so we can detect overwrites
		 * or failure to copy application information into library
		 * memory.
		 */
		if (recno)
			cursor->set_key(cursor, (uint64_t)1);
		else {
			strcpy(keybuf, KEY);
			cursor->set_key(cursor, keybuf);
		}
		strcpy(valuebuf, VALUE);
		cursor->set_value(cursor, valuebuf);

		/*
		 * The application must keep key and value memory valid until
		 * the next operation that positions the cursor, modifies the
		 * data, or resets or closes the cursor.
		 *
		 * Modifying either the key or value buffers is not permitted.
		 */
		switch (op->func) {
		case INSERT:
			testutil_check(cursor->insert(cursor));
			break;
		case SEARCH:
			testutil_check(cursor->search(cursor));
			break;
		case SEARCH_NEAR:
			testutil_check(cursor->search_near(cursor, &exact));
			break;
		case REMOVE_POS:
			/*
			 * Remove has two modes, one where the remove is based
			 * on a cursor position, the other where it's based on
			 * a set key. The results are different, so test them
			 * separately.
			 */
			testutil_check(cursor->search(cursor));
			/* FALLTHROUGH */
		case REMOVE:
			testutil_check(cursor->remove(cursor));
			break;
		case RESERVE:
#if 0
			testutil_check(cursor->reserve(cursor));
#endif
			break;
		case UPDATE:
			testutil_check(cursor->update(cursor));
			break;
		}

		/*
		 * The cursor should no longer reference application memory,
		 * and application buffers can be safely overwritten.
		 */
		memset(keybuf, 'K', sizeof(keybuf));
		memset(valuebuf, 'V', sizeof(valuebuf));

		/*
		 * Check that get_key/get_value behave as expected after the
		 * operation.
		 */
		switch (op->func) {
		case INSERT:
		case REMOVE:
			/*
			 * Insert and remove configured with a search key do
			 * not position the cursor and have no key or value.
			 *
			 * There should be two error messages, ignore them.
			 */
			ignore_errors = 2;
			if (recno)
				testutil_assert(
				    cursor->get_key(cursor, &keyr) != 0);
			else
				testutil_assert(
				    cursor->get_key(cursor, &key) != 0);
			testutil_assert(cursor->get_value(cursor, &value) != 0);
			testutil_assert(ignore_errors == 0);
			break;
		case REMOVE_POS:
			/*
			 * Remove configured with a cursor position has a key,
			 * but no value.
			 *
			 * There should be one error message, ignore it.
			 */
			if (recno) {
				testutil_assert(
				    cursor->get_key(cursor, &keyr) == 0);
				testutil_assert(keyr == 1);
			} else {
				testutil_assert(
				    cursor->get_key(cursor, &key) == 0);
				testutil_assert(key != keybuf);
				testutil_assert(strcmp(key, KEY) == 0);
			}
			ignore_errors = 1;
			testutil_assert(cursor->get_value(cursor, &value) != 0);
			testutil_assert(ignore_errors == 0);
			break;
		case RESERVE:
		case SEARCH:
		case SEARCH_NEAR:
		case UPDATE:
			/*
			 * Reserve, search, search-near and update position the
			 * cursor and have both a key and value.
			 *
			 * Any key/value should not reference application
			 * memory.
			 */
			if (recno) {
				testutil_assert(
				    cursor->get_key(cursor, &keyr) == 0);
				testutil_assert(keyr == 1);
			} else {
				testutil_assert(
				    cursor->get_key(cursor, &key) == 0);
				testutil_assert(key != keybuf);
				testutil_assert(strcmp(key, KEY) == 0);
			}
			testutil_assert(cursor->get_value(cursor, &value) == 0);
			testutil_assert(value != valuebuf);
			testutil_assert(strcmp(value, VALUE) == 0);
			break;
		}

		/*
		 * We have more than one remove operation, add the key back
		 * in.
		 */
		if (op->func == REMOVE || op->func == REMOVE_POS) {
			if (recno)
				cursor->set_key(cursor, (uint64_t)1);
			else {
				cursor->set_key(cursor, KEY);
			}
			cursor->set_value(cursor, VALUE);
			testutil_check(cursor->insert(cursor));
		}
	}
}

static void
run(WT_CONNECTION *conn, const char *uri, const char *config)
{
	WT_SESSION *session;

	testutil_check(conn->open_session(conn, NULL, NULL, &session));
	testutil_check(session->create(session, uri, config));
	cursor_scope_ops(session, uri);
	testutil_check(session->close(session, NULL));
}

int
main(int argc, char *argv[])
{
	TEST_OPTS *opts, _opts;

	opts = &_opts;
	memset(opts, 0, sizeof(*opts));
	testutil_check(testutil_parse_opts(argc, argv, opts));
	testutil_make_work_dir(opts->home);

	testutil_check(
	    wiredtiger_open(opts->home, &event_handler, "create", &opts->conn));

	run(opts->conn, "file:file.SS", "key_format=S,value_format=S");
	run(opts->conn, "file:file.rS", "key_format=r,value_format=S");
	run(opts->conn, "lsm:lsm.SS", "key_format=S,value_format=S");
	run(opts->conn, "lsm:lsm.rS", "key_format=r,value_format=S");
	run(opts->conn, "table:table.SS", "key_format=S,value_format=S");
	run(opts->conn, "table:table.rS", "key_format=r,value_format=S");

	testutil_cleanup(opts);

	return (EXIT_SUCCESS);
}
