#include <stdio.h>
#include <stdlib.h>
void get_hex(char **destbuf, int *destsiz, const unsigned char *buf, int size )
{
const char hexconv[] = "0123456789ABCDEF";
#define HEXDUMP_LEN 68
    unsigned char hexstr[HEXDUMP_LEN];

    unsigned char *hex_ptr;
    const unsigned char *buf_ptr = buf;
    const unsigned char *end = buf+size;

    int i;
    int done = 0;
    int oset = 0;

    int offset = 0;

    /* Initialize the final 2 bytes, hopefully my pointer arithmatic is correct. */
    hexstr[HEXDUMP_LEN-1] = '\0';

    while( ! done )
    {
        /* Reset my pointers. */
        hex_ptr = &hexstr[0];

        /* Format 16 bytes per line. */
        for( i = 0; i<16; ++i, ++buf_ptr )
        {
            /* C string hex format */
            *hex_ptr = '\x5c';
            hex_ptr++;
            *hex_ptr ='x';
            hex_ptr++;

            /* Grab the high nybble. */
            *hex_ptr = hexconv[(*buf_ptr >> 4)];
            hex_ptr++;

            /* Grab the low nybble. */
            *hex_ptr = hexconv[(*buf_ptr & 0x0F)];
            hex_ptr++;

            /* Prematurely end formatting */
            if( (buf_ptr+1) >= end ) {
                *hex_ptr = 0x0;
                done = 1;
                break;
            }
        }

        /* Dump it to file, then increment line argcer. */
        if ( *destbuf==NULL || *destsiz-offset <= 0 ) 
        {
            size_t asksiz = 16384;
            void * temp = realloc(*destbuf, *destsiz + asksiz);
            if (!temp)
                return;
            *destbuf = temp;
            *destsiz += asksiz;
        }

        char *loc = *destbuf;
        int locsiz = *destsiz;

        loc += offset;
        locsiz -= offset;

        offset += snprintf(loc, locsiz-1, "%s", hexstr);
        oset += 16;
    }

    return;
#undef HEXDUMP_LEN
}
