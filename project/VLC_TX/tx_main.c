/*
 * test.c
 * (C) 2016, all rights reserved,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * VLC-TX side capture framework.
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#define MAX_PACKET			2048
#define MAXBUF				0xFFFF
#define MAX_CLIENT_NUMER	16

#define DBGMOD
#define FONT_RED		FOREGROUND_RED
#define FONT_GREEN		FOREGROUND_GREEN
#define FONT_BLUE		FOREGROUND_BLUE
#define FONT_MAGENTA	FOREGROUND_RED | FOREGROUND_BLUE
#define FONT_YELLOW		FOREGROUND_RED | FOREGROUND_GREEN
#define FONT_CYAN		FOREGROUND_BLUE | FOREGROUND_GREEN
#define FONT_WHITE		FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_GREEN
#define PRINTD(CSL, FMT, TXT) \
	#ifdef DBGMOD \
		SetConsoleTextAttribute(CSL, FONT_MAGENTA); \
		fputs("[DBG]", stdout); \
		SetConsoleTextAttribute(CSL, FONT_GREEN); \
		printf(FMT, TXT); \
		SetConsoleTextAttribute(CSL, FONT_WHITE); \
	#endif

typedef struct _IPMAP
{
	UINT32 ori_ip;
	UINT32 map_ip;
} IPMAP, *IPMAP;

/*
 * Prototypes.
 */
static HANDLE console;
static DWORD udpHandler(LPVOID arg);

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
	HANDLE cap_handle;

	// udp_port, cap_iface_index, cap_iface_ipAddr, frame_struct_IB

	// Get console for pretty colors.
    console = GetStdHandle(STD_OUTPUT_HANDLE);
	PRINTD(console, "%s", "TX-MAIN now on...");

	//thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)udpHandler, (LPVOID)handle, 0, NULL);
	
	//main thread
	while (True)
	{

	}
	return 0;
}

// UDP server thread.
static DWORD udpHandler(LPVOID arg)
{

}

	/*global proxy_map
	ipAddr = packet.dst_addr
	ipAddr_raw = ip2int(ipAddr)
	fraw = str(bytearray(packet.raw))

	tmp = proxy_map #atom
	for k,v in tmp.items():if ipAddr in v:fid = k

	packet = struct_helper((ipAddr_raw, fid), fraw)
	packet = "%d %s %s"%(ipAddr_raw, fid, fraw)
	packet = fraw*/


	/*count, length = 0, 0
	w = pydivert.WinDivert(flt_ctrl)
	w.open()

	while True:
		flt_ctrl = "inbound and ifIdx==%d and ip"%(iface_t[0])

		if not pkt_q.empty():
			packet = w.recv()
			udp_packet = packet_wrapper(p)
			if udp_packet:
				skt.sendto(udp_packet, ('localhost', udp_port))

				count += 1
				length += len(udp_packet)
				remains = pkt_q.qsize()
				if DBG: print("%d\t%d\t%.2f MB"%(count, remains, length/1E6))
				pass
			else:
				w.send(p) #send back others*/
