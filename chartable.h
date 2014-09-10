/*
 *  OpenVPN-GUI -- A Windows GUI for OpenVPN.
 *
 *  Copyright (C) 2004 Mathias Sundman <mathias@nilings.se>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

WCHAR unicode_to_ascii[256] = {
0x0000,
0x0001,
0x0002,
0x0003,
0x0004,
0x0005,
0x0006,
0x0007,
0x0008,
0x0009,
0x000a,
0x000b,
0x000c,
0x000d,
0x000e,
0x000f,
0x0010,
0x0011,
0x0012,
0x0013,
0x0014,
0x0015,
0x0016,
0x0017,
0x0018,
0x0019,
0x001a,
0x001b,
0x001c,
0x001d,
0x001e,
0x001f,
0x0020,
0x0021,
0x0022,
0x0023,
0x0024,
0x0025,
0x0026,
0x0027,
0x0028,
0x0029,
0x002a,
0x002b,
0x002c,
0x002d,
0x002e,
0x002f,
0x0030,
0x0031,
0x0032,
0x0033,
0x0034,
0x0035,
0x0036,
0x0037,
0x0038,
0x0039,
0x003a,
0x003b,
0x003c,
0x003d,
0x003e,
0x003f,
0x0040,
0x0041,
0x0042,
0x0043,
0x0044,
0x0045,
0x0046,
0x0047,
0x0048,
0x0049,
0x004a,
0x004b,
0x004c,
0x004d,
0x004e,
0x004f,
0x0050,
0x0051,
0x0052,
0x0053,
0x0054,
0x0055,
0x0056,
0x0057,
0x0058,
0x0059,
0x005a,
0x005b,
0x005c,
0x005d,
0x005e,
0x005f,
0x0060,
0x0061,
0x0062,
0x0063,
0x0064,
0x0065,
0x0066,
0x0067,
0x0068,
0x0069,
0x006a,
0x006b,
0x006c,
0x006d,
0x006e,
0x006f,
0x0070,
0x0071,
0x0072,
0x0073,
0x0074,
0x0075,
0x0076,
0x0077,
0x0078,
0x0079,
0x007a,
0x007b,
0x007c,
0x007d,
0x007e,
0x007f,
0x00c7,
0x00fc,
0x00e9,
0x00e2,
0x00e4,
0x00e0,
0x00e5,
0x00e7,
0x00ea,
0x00eb,
0x00e8,
0x00ef,
0x00ee,
0x00ec,
0x00c4,
0x00c5,
0x00c9,
0x00e6,
0x00c6,
0x00f4,
0x00f6,
0x00f2,
0x00fb,
0x00f9,
0x00ff,
0x00d6,
0x00dc,
0x00f8,
0x00a3,
0x00d8,
0x00d7,
0x0192,
0x00e1,
0x00ed,
0x00f3,
0x00fa,
0x00f1,
0x00d1,
0x00aa,
0x00ba,
0x00bf,
0x00ae,
0x00ac,
0x00bd,
0x00bc,
0x00a1,
0x00ab,
0x00bb,
0x2591,
0x2592,
0x2593,
0x2502,
0x2524,
0x00c1,
0x00c2,
0x00c0,
0x00a9,
0x2563,
0x2551,
0x2557,
0x255d,
0x00a2,
0x00a5,
0x2510,
0x2514,
0x2534,
0x252c,
0x251c,
0x2500,
0x253c,
0x00e3,
0x00c3,
0x255a,
0x2554,
0x2569,
0x2566,
0x2560,
0x2550,
0x256c,
0x00a4,
0x00f0,
0x00d0,
0x00ca,
0x00cb,
0x00c8,
0x0131,
0x00cd,
0x00ce,
0x00cf,
0x2518,
0x250c,
0x2588,
0x2584,
0x00a6,
0x00cc,
0x2580,
0x00d3,
0x00df,
0x00d4,
0x00d2,
0x00f5,
0x00d5,
0x00b5,
0x00fe,
0x00de,
0x00da,
0x00db,
0x00d9,
0x00fd,
0x00dd,
0x00af,
0x00b4,
0x00ad,
0x00b1,
0x2017,
0x00be,
0x00b6,
0x00a7,
0x00f7,
0x00b8,
0x00b0,
0x00a8,
0x00b7,
0x00b9,
0x00b3,
0x00b2,
0x25a0,
0x00a0
};

