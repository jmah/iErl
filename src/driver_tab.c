#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */
#include <stdio.h>
#include "global.h"

extern ErlDrvEntry efile_driver_entry;
extern ErlDrvEntry inet_driver_entry;
extern ErlDrvEntry zlib_driver_entry;
extern ErlDrvEntry ram_file_driver_entry;
extern ErlDrvEntry ttsl_driver_entry;
extern ErlDrvEntry crypto_driver_entry;
extern ErlDrvEntry couch_driver_entry;
extern ErlDrvEntry ios_driver_entry;

ErlDrvEntry *driver_tab[DRIVER_TAB_SIZE] =
{
    &efile_driver_entry,
    &inet_driver_entry,
    &zlib_driver_entry,
    &ram_file_driver_entry,
//  &ttsl_driver_entry,			// Not needed for mobile CouchDB --jens
    &couch_driver_entry,
    &crypto_driver_entry,
    &ios_driver_entry,
    NULL
};
