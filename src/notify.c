/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 * 
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * LISTEN / NOTIFY proxy handlers
 *
 * currently, this code will just maintain a map of which servers are
 * handling LISTEN channels for which clients, and migrate LISTENs over
 * to other servers when server connections are purged.
 *
 * Since notifies do not arrive inside transactions the arrival times
 * of notifications will be delayed by long running transactions.  From
 * the client perspective, this may result in choppy, unpredictable
 * delivery times.  Further work here could segregate a dedicated server
 * connection to handle LISTEN commands exclusively.
 */

#include "bouncer.h"
#include <usual/regex.h>

typedef struct PgChannelSrv PgChannelSrv;
typedef struct PgChannelCli PgChannelCli;
typedef struct PgChannelEnt PgChannelEnt;

/* rough (JS) pseudocode for data structure layout:
 *
 *   var pool   = PgPool->new({ ..., notify: {} });
 *   var client = PgSocket->new({ ..., notify: [] });
 *   var server = PgSocket->new({ ..., notify: [] });
 *   
 *   server.pool.notify['NoteA'] = PgChannelSrv->new({
 *       name: 'NoteA',
 *       server: server,
 *       clients: [],
 *   });
 *   server.notify.push(server.pool.notify['NoteA']);
 *   {
 *       var cli = PgChannelCli->new({
 *           ent: PgChannelEnt->new({
 *               client: client,
 *           }),
 *           srv: server.pool.notify['NoteA'],
 *       });
 *       client.notify.push(cli);
 *       server.pool.notify['NoteA'].clients.push(cli.ent);
 *   }
 */

struct PgChannelSrv {
	struct List head;
	PgSocket *server;
	struct StatList clients;
	unsigned len;
	char name[0];
};

struct PgChannelCli {
	struct List head;
	struct PgChannelEnt {
		struct List head;
		struct PgSocket *client;
	} ent;
	struct PgChannelSrv *srv;
};

static unsigned int nfy_key(void *ctx, void *obj, const void **dst_p)
{
	PgChannelSrv *srv = obj;
	*dst_p = srv->name;
	return srv->len;
}

static bool nfy_free(void *ctx, void *obj)
{
	PgChannelSrv *srv = obj;
	free(srv);
	return true;
}

static void nfy_send_listen(PgSocket *server, const char *channel, unsigned len)
{
	/* TODO: issue LISTEN to server */
}

static void nfy_send_unlisten(PgSocket *server, const char *channel, unsigned len)
{
	/* TODO: issue UNLISTEN to server */
}

static void nfy_client_remove(PgChannelCli *cli)
{
	statlist_remove(&cli->srv->clients, &cli->ent.head);
	list_del(&cli->head);
	if (statlist_count(&cli->srv->clients) == 0) {
		nfy_send_unlisten(cli->srv->server, cli->srv->name, cli->srv->len);
		list_del(&cli->srv->head);
		cbtree_delete(cli->ent.client->pool->notify, cli->srv->name, cli->srv->len);
	}
	free(cli);
}

/* LISTEN X from client */
static void nfy_listen(PgSocket *client, const char *channel, unsigned len)
{
	PgChannelCli *cli;
	PgChannelSrv *srv;
	struct List *item;

	slog_info(client, "notify delegation client LISTEN %.*s", len, channel);

	srv = (PgChannelSrv *)cbtree_lookup(client->pool->notify, channel, len);
	if (srv) {
		/* check for dup client entry */
		list_for_each(item, &client->notify)
			if (container_of(item, PgChannelCli, head)->srv == srv)
				return;
	} else {
		/* issue the listen first, then do the bookkeeping */
		nfy_send_listen(client->link, channel, len);

		srv = (PgChannelSrv *)calloc(1, sizeof(*srv) + len);
		srv->server = client->link;
		srv->len = len;
		memcpy(srv->name, channel, len);
		statlist_init(&srv->clients, "chansrv.clients");

		if (!cbtree_insert(client->pool->notify, srv))
			fatal("notify delegation unable to track pool");
		list_append(&srv->server->notify, &srv->head);
	}

	cli = (PgChannelCli *)calloc(1, sizeof(*cli));
	cli->ent.client = client;
	cli->srv = srv;
	list_append(&client->notify, &cli->head);
	statlist_append(&srv->clients, &cli->ent.head);
}

/* UNLISTEN X from client */
static void nfy_unlisten(PgSocket *client, const char *channel, unsigned len) {
	struct List *item;
	PgChannelCli *cli;
	PgChannelSrv *srv;

	slog_info(client, "notify delegation client UNLISTEN %.*s", len, channel);

	srv = (PgChannelSrv *)cbtree_lookup(client->pool->notify, channel, len);
	if (!srv)
		return;

	list_for_each(item, &client->notify) {
		cli = container_of(item, PgChannelCli, head);
		if (cli->srv == srv)
		    nfy_client_remove(cli);
	}
}

struct {
	const char *txt;
	bool compiled;
	regex_t rc;
	regmatch_t  rm[4];
} nfy_rx = {
	"^(un)?listen[ \t\r\n\r]*([a-z_][a-z0-9_]*|\"([^\"]+)\")[ \t\r\n\r]*;?$"
};

bool notify_scan_client(PgSocket *client, PktHdr *pkt)
{
	/* This is a big ugly hack for several reasons:
	 *
	 * 1) I doubt we'll always see the whole packet waiting in
	 *    pkt->data.
	 * 2) It only really handles PQexec(conn, "LISTEN <channel>") and
	 *    PQexec(conn, "UNLISTEN <channel>") style queries.
	 * 3) It does not realize LISTEN/UNLISTEN calls don't take effect
	 *    until the current transaction commits and never take effect if
	 *    this transaction is rolled back.
	 *
	 * These limitations may be a showstopper for your application.
	 */
	const char *query;
	unsigned    pos, len;
	const char *ch_name;
	unsigned    ch_len;
	regmatch_t *rm;

	if (0 && !cf_delegate_notify)
		return false;

	if (pkt->type != 'Q')
		return false;

	pos = mbuf_consumed(&pkt->data);
	len = pkt->len - pos;

	if (!mbuf_get_chars(&pkt->data, len, &query))
		return false;

	/* TODO: the regex used here could definitely be improved,
	 * serving mainly as a proof of concept.  It's unclear at this
	 * point how much scanning the queries as they flow through
	 * bouncer will cost, but well written regexes should't be too
	 * far from optimal. */
	if (!nfy_rx.compiled) {
		if (regcomp(&nfy_rx.rc, nfy_rx.txt, REG_EXTENDED | REG_ICASE))
			fatal("notify regex compilation error");
		nfy_rx.compiled = true;
	}
	if (regexec(&nfy_rx.rc, query, sizeof(nfy_rx.rm) / sizeof(nfy_rx.rm[0]), nfy_rx.rm, 0) != 0)
		return false;

	if (!client->pool->notify)
		client->pool->notify = cbtree_create(nfy_key, nfy_free, NULL, USUAL_ALLOC);

	rm = nfy_rx.rm + 3;
	if (rm->rm_so > 0) {              /* channel was quoted */
		ch_name = query + rm->rm_so;
		ch_len  = rm->rm_eo - rm->rm_so;
	} else {                            /* channel was bare */
		rm = nfy_rx.rm + 2;
		ch_name = query + rm->rm_so;
		ch_len  = rm->rm_eo - rm->rm_so;
	}
	rm = nfy_rx.rm + 1;
	if (rm->rm_so == rm->rm_eo)     /* matched ()LISTEN */
		nfy_listen(client, ch_name, ch_len);
	else                                /* matched (UN)LISTEN */
		nfy_unlisten(client, ch_name, ch_len);

	/* reset reader position */
	mbuf_rewind_reader(&pkt->data);
	if (mbuf_get_chars(&pkt->data, pos, &query)) {}

	sbuf_prepare_send(&client->sbuf, &client->link->sbuf, pkt->len);

	return true;
}

bool notify_scan_server(PgSocket *server, PktHdr *pkt)
{
	unsigned pos, len;
	PgChannelSrv *srv;
	PgChannelEnt *ent;
	struct List *item;
	uint32_t pid;
	const char *name;
	const char *extra;
	PktBuf *buf;

	if (!server->pool->notify)
		return false;

	if (pkt->type != 'A')
		return false;

	pos = mbuf_consumed(&pkt->data);
	len = pkt->len - pos;
	if (!(mbuf_get_uint32be(&pkt->data, &pid) &&
		    mbuf_get_string(&pkt->data, &name) &&
		    mbuf_get_string(&pkt->data, &extra))) {
		slog_error(server, "notify delegation saw partial NotificationResponse packet");
		mbuf_rewind_reader(&pkt->data);
		if(mbuf_get_chars(&pkt->data, pos, &name)) {};
		return false;
	}

	srv = (PgChannelSrv *)cbtree_lookup(server->pool->notify, name, strlen(name));
	if (srv) {
		slog_noise(server, "notify delegation NotificationResponse %s => %d", name, statlist_count(&srv->clients));
		statlist_for_each(item, &srv->clients) {
			ent = container_of(item, PgChannelEnt, head);
			buf = pktbuf_dynamic(pkt->len);
			pktbuf_write_NotificationResponse(buf, pid, name, extra);
			if (!pktbuf_send_queued(buf, ent->client)) {
				slog_noise(ent->client, "notify delegation unable to write");
			}
		}
	}
	sbuf_prepare_skip(&server->sbuf, pkt->len);
	return true;
}

/* disconnect_server */
void notify_server_cleanup(PgSocket *server)
{
	PgSocket *other;
	PgChannelSrv *srv;
	struct List *item;

	if (!server->pool->notify)
		return;

	if (list_empty(&server->notify))
		return;

	statlist_for_each(item, &server->pool->idle_server_list) {
		other = container_of(item, PgSocket, head);
		if (other != server)
			goto FOUND_other;
	}
	statlist_for_each(item, &server->pool->active_server_list) {
		other = container_of(item, PgSocket, head);
		if (other != server)
			goto FOUND_other;
	}
	other = NULL;

FOUND_other:

	while((srv = list_pop_type(&server->notify, PgChannelSrv, head))) {
		if (other) {
			slog_info(server, "notify delegation migrate %.*s", srv->len, srv->name);
			nfy_send_listen(other, srv->name, srv->len);
			srv->server = other;
			list_append(&other->notify, &srv->head);
		} else {
			/* TODO: this error condition could be avoided
			 * by forcing a min_pool_size > 1 from the
			 * config or by having notifications handled by
			 * a dedicated connection.  If a connection were
			 * dedicated to this purpose, it would be best
			 * to have that connection the first to open and
			 * the last to close. */
			slog_error(srv->server, "notify delegation migrate %.*s failed", srv->len, srv->name);
		}
		/* the server side can clean up for itself when we disconnect
		nfy_send_unlisten(server, srv->name, srv->len);
		 */
	}
}

/* disconnect_client */
void notify_client_cleanup(PgSocket *client)
{
	PgChannelCli *cli;

	if (!client->pool->notify)
		return;

	while((cli = list_pop_type(&client->notify, PgChannelCli, head))) {
		slog_info(client, "notify delegation client UNLISTEN %s (implicit)", cli->srv->name);
		nfy_client_remove(cli);
	}
}
