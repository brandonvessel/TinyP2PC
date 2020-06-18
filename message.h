/*
This file is part of TinyP2PC

Github: https://github.com/brandonvessel/TinyP2PC

THIS LICENSE MUST REMAIN AT THE TOP OF THIS FILE

TinyP2PC is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

TinyP2PC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TinyP2PC.  If not, see <https://www.gnu.org/licenses/>.
*/
#pragma once

typedef struct message_header_t {
	char type;
	uint32_t payload_length; // useful length of the payload for most protocols
    uint32_t message_length; // length of the command in the payload portion of the packet
} message_header;


typedef struct packet_t {
	struct message_header_t header;
	char payload[240];   // this is the maximum payload length
    char encrypted[256]; // size of encrypted payload after RSA encrypted
} packet;
