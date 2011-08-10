#include <CoreFoundation/CFNotificationCenter.h>
#include <UIKit/UIApplication.h>

#include "erl_driver.h"
#include "erl_nif.h"
#include "util.h" //from emonk

/* Driver interface declarations */
int iosdrv_init(void);
ErlDrvData iosdrv_start(ErlDrvPort port, char *command);
int iosdrv_control(ErlDrvData drv_data, unsigned int command, char *buf,
                   int len, char **rbuf, int rlen);

ErlDrvEntry ios_driver_entry = {
    iosdrv_init,
    iosdrv_start,
    NULL,
    NULL,                       /* output */
    NULL,                       /* ready_input */
    NULL,                       /* ready_output */
    "ios_drv",
    NULL,                       /* finish */
    NULL,                       /* handle */
    iosdrv_control,
    NULL,                       /* timeout */
    NULL,                       /* outputv */
    NULL,                       /* ready_async */
    NULL,                       /* flush */
    NULL,                       /* call */
    NULL,                       /* event */
    ERL_DRV_EXTENDED_MARKER,
    ERL_DRV_EXTENDED_MAJOR_VERSION,
    ERL_DRV_EXTENDED_MINOR_VERSION,
    ERL_DRV_FLAG_USE_PORT_LOCKING, /* flags */
    NULL,                       /* handle2 */
    NULL                        /* process_exit */
};

static ErlDrvTermData iosdrv_foregrounded = 0;
static ErlDrvTermData iosdrv_process = 0;
static ErlDrvPort iosdrv_port = 0;
static int couchdb_port = 0;

void notificationCallback (CFNotificationCenterRef center,
                           void * observer,
                           CFStringRef name,
                           const void * object,
                           CFDictionaryRef userInfo) {
    NSLog(@"Got return from foreground notification.");
    if(iosdrv_process != 0)
    {
        ErlDrvTermData term[] = {ERL_DRV_ATOM, iosdrv_foregrounded, ERL_DRV_TUPLE, 1};
        driver_send_term(iosdrv_port, iosdrv_process, term, sizeof(term) / sizeof(term[0]));
        iosdrv_process = 0;
    }
}

int iosdrv_init(void)
{
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(), NULL,
            notificationCallback, (CFStringRef) UIApplicationWillEnterForegroundNotification,
            NULL, CFNotificationSuspensionBehaviorCoalesce);
    return 0;
}

ErlDrvData iosdrv_start(ErlDrvPort port, char *command)
{
    set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);
    iosdrv_foregrounded = driver_mk_atom("foregrounded");
    iosdrv_process = driver_connected(port);
    iosdrv_port = port;
    return 0;
}

int iosdrv_control(ErlDrvData drv_data, unsigned int command, char *buf,
              int len, char **rbuf, int rlen)
{
    return -1;
}


ERL_NIF_TERM set_port(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int a;
    if (!enif_get_int(env, argv[0], &a)) {
        return enif_make_badarg(env);
    }
    couchdb_port = a;
    return util_mk_atom(env, "ok");
}

ERL_NIF_TERM get_port(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return enif_make_int(env, couchdb_port);
}


//We're also a NIF for preserving the port number across the VM restart
static ErlNifFunc ios_nif_funcs[] =
{
    {"set_port", 1, set_port},
    {"get_port", 0, get_port}
};

ERL_NIF_INIT(couch_ios, ios_nif_funcs, NULL, NULL, NULL, NULL);
