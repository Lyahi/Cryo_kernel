/*
 * Driver for USB Attached SCSI devices - Unusual Devices File
 *
 *   (c) 2013 Hans de Goede <hdegoede@redhat.com>
 *
 * Based on the same file for the usb-storage driver, which is:
 *   (c) 2000-2002 Matthew Dharm (mdharm-usb@one-eyed-alien.net)
 *   (c) 2000 Adam J. Richter (adam@yggdrasil.com), Yggdrasil Computing, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * IMPORTANT NOTE: This file must be included in another file which defines
 * a UNUSUAL_DEV macro before this file is included.
 */

/*
 * If you edit this file, please try to keep it sorted first by VendorID,
 * then by ProductID.
 *
 * If you want to add an entry for this file, be sure to include the
 * following information:
 *	- a patch that adds the entry for your device, including your
 *	  email address right above the entry (plus maybe a brief
 *	  explanation of the reason for the entry),
 *	- lsusb -v output for the device
 * Send your submission to Hans de Goede <hdegoede@redhat.com>
 * and don't forget to CC: the USB development list <linux-usb@vger.kernel.org>
 */

/* Reported-by: Till Dörges <doerges@pre-sense.de> */
UNUSUAL_DEV(0x054c, 0x087d, 0x0000, 0x9999,
		"Sony",
		"PSZ-HA*",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_REPORT_OPCODES),

/*
 *  Initially Reported-by: Julian Groß <julian.g@posteo.de>
 *  Further reports David C. Partridge <david.partridge@perdrix.co.uk>
 */
UNUSUAL_DEV(0x059f, 0x105f, 0x0000, 0x9999,
		"LaCie",
		"2Big Quadra USB3",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_REPORT_OPCODES | US_FL_NO_SAME),

/* Reported-by: Julian Sikorski <belegdol@gmail.com> */
UNUSUAL_DEV(0x059f, 0x1061, 0x0000, 0x9999,
		"LaCie",
		"Rugged USB3-FW",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_REPORT_OPCODES | US_FL_NO_SAME),

/*
 * Apricorn USB3 dongle sometimes returns "USBSUSBSUSBS" in response to SCSI
 * commands in UAS mode.  Observed with the 1.28 firmware; are there others?
 */
UNUSUAL_DEV(0x0984, 0x0301, 0x0128, 0x0128,
		"Apricorn",
		"",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_UAS),

/* https://bugzilla.kernel.org/show_bug.cgi?id=79511 */
UNUSUAL_DEV(0x0bc2, 0x2312, 0x0000, 0x9999,
		"Seagate",
		"Expansion Desk",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* https://bbs.archlinux.org/viewtopic.php?id=183190 */
UNUSUAL_DEV(0x0bc2, 0x3312, 0x0000, 0x9999,
		"Seagate",
		"Expansion Desk",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* Reported-by: David Webb <djw@noc.ac.uk> */
UNUSUAL_DEV(0x0bc2, 0x331a, 0x0000, 0x9999,
		"Seagate",
		"Expansion Desk",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_REPORT_LUNS),

/* Reported-by: Hans de Goede <hdegoede@redhat.com> */
UNUSUAL_DEV(0x0bc2, 0x3320, 0x0000, 0x9999,
		"Seagate",
		"Expansion Desk",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* Reported-by: Bogdan Mihalcea <bogdan.mihalcea@infim.ro> */
UNUSUAL_DEV(0x0bc2, 0xa003, 0x0000, 0x9999,
		"Seagate",
		"Backup Plus",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* Reported-by: Marcin Zajączkowski <mszpak@wp.pl> */
UNUSUAL_DEV(0x0bc2, 0xa013, 0x0000, 0x9999,
		"Seagate",
		"Backup Plus",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* Reported-by: Hans de Goede <hdegoede@redhat.com> */
UNUSUAL_DEV(0x0bc2, 0xa0a4, 0x0000, 0x9999,
		"Seagate",
		"Backup Plus Desk",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* https://bbs.archlinux.org/viewtopic.php?id=183190 */
UNUSUAL_DEV(0x0bc2, 0xab20, 0x0000, 0x9999,
		"Seagate",
		"Backup+ BK",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* https://bbs.archlinux.org/viewtopic.php?id=183190 */
UNUSUAL_DEV(0x0bc2, 0xab21, 0x0000, 0x9999,
		"Seagate",
		"Backup+ BK",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* Reported-by: G. Richard Bellamy <rbellamy@pteradigm.com> */
UNUSUAL_DEV(0x0bc2, 0xab2a, 0x0000, 0x9999,
		"Seagate",
		"BUP Fast HDD",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* Reported-by: Benjamin Tissoires <benjamin.tissoires@redhat.com> */
UNUSUAL_DEV(0x13fd, 0x3940, 0x0000, 0x9999,
		"Initio Corporation",
		"INIC-3069",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X | US_FL_IGNORE_RESIDUE),

/* Reported-by: Tom Arild Naess <tanaess@gmail.com> */
UNUSUAL_DEV(0x152d, 0x0539, 0x0000, 0x9999,
		"JMicron",
		"JMS539",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_REPORT_OPCODES),

/* Reported-by: Claudio Bizzarri <claudio.bizzarri@gmail.com> */
UNUSUAL_DEV(0x152d, 0x0567, 0x0000, 0x9999,
		"JMicron",
		"JMS567",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_BROKEN_FUA | US_FL_NO_REPORT_OPCODES),

/* Reported-by: David Kozub <zub@linux.fjfi.cvut.cz> */
UNUSUAL_DEV(0x152d, 0x0578, 0x0000, 0x9999,
		"JMicron",
		"JMS567",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_BROKEN_FUA),

/* Reported by: Yaroslav Furman <yaro330@gmail.com> */
UNUSUAL_DEV(0x152d, 0x0583, 0x0000, 0x9999,
		"JMicron",
		"JMS583Gen 2",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_REPORT_OPCODES),

/* Reported-by: Thinh Nguyen <thinhn@synopsys.com> */
UNUSUAL_DEV(0x154b, 0xf00b, 0x0000, 0x9999,
		"PNY",
		"Pro Elite SSD",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* Reported-by: Thinh Nguyen <thinhn@synopsys.com> */
UNUSUAL_DEV(0x154b, 0xf00d, 0x0000, 0x9999,
		"PNY",
		"Pro Elite SSD",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* Reported-by: Hans de Goede <hdegoede@redhat.com> */
UNUSUAL_DEV(0x2109, 0x0711, 0x0000, 0x9999,
		"VIA",
		"VL711",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_ATA_1X),

/* Reported-by: Icenowy Zheng <icenowy@aosc.io> */
UNUSUAL_DEV(0x2537, 0x1068, 0x0000, 0x9999,
		"Norelsys",
		"NS1068X",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_UAS),

/*
 * Initially Reported-by: Takeo Nakayama <javhera@gmx.com>
 * UAS Ignore Reported by Steven Ellis <sellis@redhat.com>
 */
UNUSUAL_DEV(0x357d, 0x7788, 0x0000, 0x9999,
		"JMicron",
		"JMS566",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_REPORT_OPCODES | US_FL_IGNORE_UAS),

/* Reported-by: Hans de Goede <hdegoede@redhat.com> */
UNUSUAL_DEV(0x4971, 0x1012, 0x0000, 0x9999,
		"Hitachi",
		"External HDD",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_IGNORE_UAS),

/* Reported-by: Richard Henderson <rth@redhat.com> */
UNUSUAL_DEV(0x4971, 0x8017, 0x0000, 0x9999,
		"SimpleTech",
		"External HDD",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_NO_REPORT_OPCODES),

/* "G-DRIVE" external HDD hangs on write without these.
 * Patch submitted by Alexander Kappner <agk@godking.net>
 */
UNUSUAL_DEV(0x4971, 0x8024, 0x0000, 0x9999,
		"SimpleTech",
		"External HDD",
		USB_SC_DEVICE, USB_PR_DEVICE, NULL,
		US_FL_ALWAYS_SYNC),
