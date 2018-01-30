/*
 * passthru.c
 * (C) 2018, all rights reserved,
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
 * DESCRIPTION:
 * This program does nothing except divert packets and re-inject them.  This is
 * useful for performance testing.
 *
 * usage: netdump.exe windivert-filter num-threads
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define MAXBUF  0xFFFF

static DWORD passthru(LPVOID arg);

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, thread;

    // Divert traffic matching the filter:
    handle = WinDivertOpen("outbound and tcp", WINDIVERT_LAYER_NETWORK, (INT16)(-1000), 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER)
        {
            fprintf(stderr, "error: filter syntax error\n");
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Start the threads
    //for (i = 1; i < num_threads; i++)
    //{
    //    thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)passthru,
    //        (LPVOID)handle, 0, NULL);
    //    if (thread == NULL)
    //    {
    //        fprintf(stderr, "error: failed to start passthru thread (%u)\n",
    //            GetLastError());
    //        exit(EXIT_FAILURE);
    //    }
    //}

    // Main thread:
    passthru((LPVOID)handle);

    return 0;
}

// Passthru thread.
static DWORD passthru(LPVOID arg)
{
    unsigned char packet[MAXBUF];
    UINT packet_len, counter = 0;
    WINDIVERT_ADDRESS addr;

	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;

    HANDLE handle = (HANDLE)arg;

    // Main loop:
    while (TRUE)
    {
        // Read a matching packet.
        if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }
		else {
			fprintf(stdout, "Running.\n");
			WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL, NULL);
			fprintf(stdout, "SYN:%u ACK:%u FIN:%u\n", tcp_header->Syn, tcp_header->Ack, tcp_header->Fin);
		}

        // Re-inject the matching packet.
        if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
        {
			
            fprintf(stderr, "warning: failed to reinject packet (%d)\n",
                GetLastError());
        }
		else {
			counter++;
			fprintf(stdout, "%d Sent.", counter);
		}
    }
}

