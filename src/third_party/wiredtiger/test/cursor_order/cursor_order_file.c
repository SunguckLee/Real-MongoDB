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

#include "cursor_order.h"

static void
file_create(SHARED_CONFIG *cfg, const char *name)
{
	WT_CONNECTION *conn;
	WT_SESSION *session;
	int ret;
	char config[128];

	conn = cfg->conn;

	if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0)
		testutil_die(ret, "conn.session");

	testutil_check(__wt_snprintf(config, sizeof(config),
	    "key_format=%s,"
	    "internal_page_max=%d,"
	    "split_deepen_min_child=200,"
	    "leaf_page_max=%d,"
	    "%s",
	    cfg->ftype == ROW ? "S" : "r", 16 * 1024, 128 * 1024,
	    cfg->ftype == FIX ? ",value_format=3t" : ""));

	if ((ret = session->create(session, name, config)) != 0)
		if (ret != EEXIST)
			testutil_die(ret, "session.create");

	if ((ret = session->close(session, NULL)) != 0)
		testutil_die(ret, "session.close");
}

void
load(SHARED_CONFIG *cfg, const char *name)
{
	WT_CONNECTION *conn;
	WT_CURSOR *cursor;
	WT_ITEM *value, _value;
	WT_SESSION *session;
	size_t len;
	uint64_t keyno;
	int ret;
	char keybuf[64], valuebuf[64];

	conn = cfg->conn;

	file_create(cfg, name);

	if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0)
		testutil_die(ret, "conn.session");

	if ((ret =
	    session->open_cursor(session, name, NULL, "bulk", &cursor)) != 0)
		testutil_die(ret, "cursor.open");

	value = &_value;
	for (keyno = 1; keyno <= cfg->nkeys; ++keyno) {
		if (cfg->ftype == ROW) {
			testutil_check(__wt_snprintf(
			    keybuf, sizeof(keybuf), "%016" PRIu64, keyno));
			cursor->set_key(cursor, keybuf);
		} else
			cursor->set_key(cursor, (uint32_t)keyno);
		value->data = valuebuf;
		if (cfg->ftype == FIX)
			cursor->set_value(cursor, 0x01);
		else {
			testutil_check(__wt_snprintf_len_set(
			    valuebuf, sizeof(valuebuf),
			    &len, "%37" PRIu64, keyno));
			value->size = (uint32_t)len;
			cursor->set_value(cursor, value);
		}
		if ((ret = cursor->insert(cursor)) != 0)
			testutil_die(ret, "cursor.insert");
	}

	/* Setup the starting key range for the workload phase. */
	cfg->key_range = cfg->nkeys;
	if ((ret = cursor->close(cursor)) != 0)
		testutil_die(ret, "cursor.close");
	if ((ret = session->checkpoint(session, NULL)) != 0)
		testutil_die(ret, "session.checkpoint");

	if ((ret = session->close(session, NULL)) != 0)
		testutil_die(ret, "session.close");
}

void
verify(SHARED_CONFIG *cfg, const char *name)
{
	WT_CONNECTION *conn;
	WT_SESSION *session;
	int ret;

	conn = cfg->conn;

	if ((ret = conn->open_session(conn, NULL, NULL, &session)) != 0)
		testutil_die(ret, "conn.session");

	if ((ret = session->verify(session, name, NULL)) != 0)
		testutil_die(ret, "session.create");

	if ((ret = session->close(session, NULL)) != 0)
		testutil_die(ret, "session.close");
}
