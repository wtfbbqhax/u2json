// unified2json.c - unified2 -to-> JSON.
//
// $ u2 [file] count 
//
// Victor Roemer <vroemer@badsec.org>
// Wed May 20 22:01:12 EDT 2015
// Thu May 21 10:23:07 EDT 2015

#define U2JSON_VERSION "1"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jansson.h>
#include <unified2.h>

#include <assert.h>

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <time.h>

#include "hex.h"

#ifndef JANSSON_FLAGS
#define JANSSON_FLAGS  (JSON_COMPACT)
#endif

//argv[1]
static char * filename;

//argv[2] 
static bool counting = false;
static int  count;

// dynamically allocated buffer for packet bytes
static char *destbuf = NULL;
static int bufsiz = 0;

static void cleanup(void)
{
    if (destbuf && bufsiz) {
        free(destbuf);
        destbuf = NULL;
        bufsiz = 0;
    }
}

// Codes below convert the Unified2 records into JSON
void json_pack_Unified2Event(json_error_t *error, json_t **json, Unified2Event *event)
{
    assert(error != NULL);
    assert(json != NULL);
    assert(event != NULL);

    char ip_source[INET6_ADDRSTRLEN+1];
    char ip_destination[INET6_ADDRSTRLEN+1];

    inet_ntop(AF_INET, &event->ip_source, ip_source, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &event->ip_destination, ip_destination, INET_ADDRSTRLEN);

    *json = json_pack_ex(error, 0, "{s:{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:s,s:s,s:i,s:i,s:i,s:i}}", "Event",
                         "sensor_id", event->sensor_id,
                         "event_id", event->event_id,
                         "event_second", event->event_second,
                         "event_microsecond", event->event_microsecond,
                         "signature_id", event->signature_id,
                         "generator_id", event->generator_id,
                         "signature_revision", event->signature_revision,
                         "classification_id", event->classification_id,
                         "priority_id", event->priority_id,
                         "ip_source", ip_source,
                         "ip_destination", ip_destination,
                         "sport_itype", event->sport_itype,
                         "dport_icode", event->dport_icode,
                         "protocol", event->protocol,
                         "packet_action", event->packet_action);
}

void json_pack_Unified2Eventv2(json_error_t *error, json_t **json, Unified2Event_v2 *event)
{
    assert(error != NULL);
    assert(json != NULL);
    assert(event != NULL);

    char ip_source[INET6_ADDRSTRLEN+1];
    char ip_destination[INET6_ADDRSTRLEN+1];

    inet_ntop(AF_INET, &event->ip_source, ip_source, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &event->ip_destination, ip_destination, INET_ADDRSTRLEN);

    *json=json_pack_ex(error, 0, "{s:{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:s,s:s,s:i,s:i,s:i,s:i,s:i,s:i,s:i}}", "Event",
                       "sensor_id", event->sensor_id,
                       "event_id", event->event_id,
                       "event_second", event->event_second,
                       "event_microsecond", event->event_microsecond,
                       "signature_id", event->signature_id,
                       "generator_id", event->generator_id,
                       "signature_revision", event->signature_revision,
                       "classification_id", event->classification_id,
                       "priority_id", event->priority_id,
                       "ip_source", ip_source,
                       "ip_destination", ip_destination,
                       "sport_itype", event->sport_itype,
                       "dport_icode", event->dport_icode,
                       "protocol", event->protocol,
                       "packet_action", event->packet_action,
                       "mpls_label", event->mpls_label,
                       "vlan_id", event->vlan_id,
                       "policy_id", event->policy_id);
}

void json_pack_Unified2Event6(json_error_t *error, json_t **json, Unified2Event6 *event)
{
    assert(error != NULL);
    assert(json != NULL);
    assert(event != NULL);

    char ip_source[INET6_ADDRSTRLEN+1];
    char ip_destination[INET6_ADDRSTRLEN+1];

    inet_ntop(AF_INET6, &event->ip_source, ip_source, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &event->ip_destination, ip_destination, INET6_ADDRSTRLEN);

    *json=json_pack_ex(error, 0, "{s:{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:s,s:s,s:i,s:i,s:i,s:i}}", "Event",
                       "sensor_id", event->sensor_id,
                       "event_id", event->event_id,
                       "event_second", event->event_second,
                       "event_microsecond", event->event_microsecond,
                       "signature_id", event->signature_id,
                       "generator_id", event->generator_id,
                       "signature_revision", event->signature_revision,
                       "classification_id", event->classification_id,
                       "priority_id", event->priority_id,
                       "ip_source", ip_source,
                       "ip_destination", ip_destination,
                       "sport_itype", event->sport_itype,
                       "dport_icode", event->dport_icode,
                       "protocol", event->protocol,
                       "packet_action", event->packet_action);
}

void json_pack_Unified2Event6v2(json_error_t *error, json_t **json, Unified2Event6_v2 *event)
{
    assert(error != NULL);
    assert(json != NULL);
    assert(event != NULL);

    char ip_source[INET6_ADDRSTRLEN+1];
    char ip_destination[INET6_ADDRSTRLEN+1];

    inet_ntop(AF_INET6, &event->ip_source, ip_source, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &event->ip_destination, ip_destination, INET6_ADDRSTRLEN);

    *json=json_pack_ex(error, 0, "{s:{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:s,s:s,s:i,s:i,s:i,s:i,s:i,s:i,s:i}}", "Event",
                       "sensor_id", event->sensor_id,
                       "event_id", event->event_id,
                       "event_second", event->event_second,
                       "event_microsecond", event->event_microsecond,
                       "signature_id", event->signature_id,
                       "generator_id", event->generator_id,
                       "signature_revision", event->signature_revision,
                       "classification_id", event->classification_id,
                       "priority_id", event->priority_id,
                       "ip_source", ip_source,
                       "ip_destination", ip_destination,
                       "sport_itype", event->sport_itype,
                       "dport_icode", event->dport_icode,
                       "protocol", event->protocol,
                       "packet_action", event->packet_action,
                       "mpls_label", event->mpls_label,
                       "vlan_id", event->vlan_id,
                       "policy_id", event->policy_id);
}

void json_pack_Unified2Packet(json_error_t *error, json_t **json, Unified2Packet *event, uint8_t *data)
{
    assert(error != NULL);
    assert(json != NULL);
    assert(event != NULL);

    if (destbuf && bufsiz > 0)
        destbuf[0] = '\0';

    get_hex(&destbuf, &bufsiz, data, event->packet_length);

    *json=json_pack_ex(error, 0, "{s:{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:s}}", "Packet",
                       "sensor_id", event->sensor_id,
                       "event_id", event->event_id,
                       "event_second", event->event_second,
                       "packet_second", event->packet_second,
                       "packet_microsecond", event->packet_microsecond,
                       "linktype", event->linktype,
                       "packet_length", event->packet_length,
                       "packet_data", destbuf);
}

// This calls json_pack() with the above format template to write 
// various event records.
int json_pack_Unified2(json_error_t *error, json_t **json, Unified2Entry *entry)
{
    if( entry == NULL || entry->record == NULL )
        return -1;

    switch (entry->record->type) {
        case UNIFIED2_IDS_EVENT:
        json_pack_Unified2Event(error, json, entry->event);
        break;

        case UNIFIED2_IDS_EVENT_IPV6:
        json_pack_Unified2Event6(error, json, entry->event6);
        break;

        case UNIFIED2_IDS_EVENT_V2:
        json_pack_Unified2Eventv2(error, json, entry->event_v2);
        break;

        case UNIFIED2_IDS_EVENT_IPV6_V2:
        json_pack_Unified2Event6v2(error, json, entry->event6_v2);
        break;

        case UNIFIED2_PACKET:
        json_pack_Unified2Packet(error, json, entry->packet, entry->packet_data);
        break;
    }
    return 0;
}



// |prior| is special case for ',' delimiting correctness.
int to_json(Unified2Entry *entry, int *prior)
{
    json_error_t error;
    json_t *json = NULL;

    json_pack_Unified2(&error, &json, entry);

    if (!json)
        return 0;

    if (*prior)
        fputc(',', stdout); 

    *prior=1;

    json_dumpf(json, stdout, JANSSON_FLAGS);
    json_decref(json);

    return 1;
}

int loop_to_json(const char *filename)
{
    int prior = 0;

    Unified2 *unified2 = NULL;
    Unified2Entry *entry = NULL;

    unified2 = Unified2New();
    entry = Unified2EntryNew();

    // TODO: fix unified2 code for const
    if (filename)
        Unified2ReadOpenFILE(unified2, (char*)filename);
    else
        Unified2ReadOpenFILE_2(unified2, stdin);

    fputc('[', stdout);
    for (;;)
    {
        int r = Unified2ReadNextEntry(unified2, entry);

        if (entry == NULL || entry->record == NULL)
            break;

        if (r == UNIFIED2_EOF)
        {
            Unified2EntrySparseCleanup(entry);
            continue;
        }

        if (to_json(entry, &prior))
        {
            if (counting)
            {
                if (--count <= 0)
                {
                    Unified2EntrySparseCleanup(entry);
                    break;
                }
            }
        }
        Unified2EntrySparseCleanup(entry);
    }
    fputc(']', stdout);

    free(entry);
    Unified2Free(unified2);

    return 1;
}

int parse_args(int argc, char *argv[])
{
    if (argc >= 2)
    {
        filename = argv[1];
    }
    if (argc >= 3) 
    {
        counting = true;
        count = atoi(argv[2]);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    atexit(cleanup);

    if (parse_args(argc, argv)) {
        fprintf(stderr, "Usage: u2 <FILE> [Number]\n");
        exit(1);
    }

    loop_to_json(filename);

    return 0;
}
