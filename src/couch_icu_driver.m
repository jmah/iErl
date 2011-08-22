/*

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

*/

// This file is the C port driver for Erlang. It provides a low overhead
// means of calling into C code, however coding errors in this module can
// crash the entire Erlang server.


#include "erl_driver.h"
#include <CoreFoundation/CFString.h>

typedef struct {
    ErlDrvPort port;
} couch_drv_data;

static void couch_drv_stop(ErlDrvData data)
{
}

static ErlDrvData couch_drv_start(ErlDrvPort port, char *buff)
{
    return NULL;
}

static int return_control_result(void* pLocalResult, int localLen, char **ppRetBuf, int returnLen)
{
    if (*ppRetBuf == NULL || localLen > returnLen) {
        *ppRetBuf = (char*)driver_alloc_binary(localLen);
        if(*ppRetBuf == NULL) {
            return -1;
        }
    }
    memcpy(*ppRetBuf, pLocalResult, localLen);
    return localLen;
}

static int couch_drv_control(ErlDrvData drv_data, unsigned int command, char *pBuf,
             int bufLen, char **rbuf, int rlen)
{
    switch(command) {
    case 0: // COLLATE
    case 1: // COLLATE_NO_CASE:
        {
	    uint32_t length;
	    char response;
	    // 2 strings are in the buffer, consecutively
	    // The strings begin first with a 32 bit integer byte length, then the actual
	    // string bytes follow.

	    // first 32bits are the length
	    memcpy(&length, pBuf, sizeof(length));
	    pBuf += sizeof(length);
	    CFStringRef str_a = CFStringCreateWithBytesNoCopy(NULL, (const uint8_t*)pBuf, length,
							      kCFStringEncodingUTF8, NO,
							      kCFAllocatorNull);
	    if (!str_a) {
		return -1;	// error -- ureadable UTF-8
	    }

	    pBuf += length; // now on to string b

	    // first 32bits are the length
	    memcpy(&length, pBuf, sizeof(length));
	    pBuf += sizeof(length);
	    CFStringRef str_b = CFStringCreateWithBytesNoCopy(NULL, (const uint8_t*)pBuf, length,
							      kCFStringEncodingUTF8, NO,
							      kCFAllocatorNull);
	    if (!str_b) {
		CFRelease(str_a);
		return -1;	// error -- ureadable UTF-8
	    }

	    CFStringCompareFlags flags = kCFCompareAnchored;
	    if (command == 1)
		flags |= kCFCompareCaseInsensitive;

	    CFComparisonResult collResult = CFStringCompare(str_a, str_b, flags);

	    if (collResult == kCFCompareLessThan)
		response = 0; //lt
	    else if (collResult == kCFCompareGreaterThan)
		response = 2; //gt
	    else
		response = 1; //eq (NSOrderedSame)

	    CFRelease(str_a);
	    CFRelease(str_b);
	    return return_control_result(&response, sizeof(response), rbuf, rlen);
        }
    default:
        return -1;
    }
}

ErlDrvEntry couch_driver_entry = {
        NULL,               /* F_PTR init, N/A */
        couch_drv_start,    /* L_PTR start, called when port is opened */
        couch_drv_stop,     /* F_PTR stop, called when port is closed */
        NULL,               /* F_PTR output, called when erlang has sent */
        NULL,               /* F_PTR ready_input, called when input descriptor ready */
        NULL,               /* F_PTR ready_output, called when output descriptor ready */
        "couch_icu_driver", /* char *driver_name, the argument to open_port */
        NULL,               /* F_PTR finish, called when unloaded */
        NULL,               /* Not used */
        couch_drv_control,  /* F_PTR control, port_command callback */
        NULL,               /* F_PTR timeout, reserved */
        NULL,               /* F_PTR outputv, reserved */
        NULL,               /* F_PTR ready_async */
        NULL,               /* F_PTR flush */
        NULL,               /* F_PTR call */
        NULL,               /* F_PTR event */
        ERL_DRV_EXTENDED_MARKER,
        ERL_DRV_EXTENDED_MAJOR_VERSION,
        ERL_DRV_EXTENDED_MINOR_VERSION,
        ERL_DRV_FLAG_USE_PORT_LOCKING,
        NULL,               /* Reserved -- Used by emulator internally */
        NULL,               /* F_PTR process_exit */
};

