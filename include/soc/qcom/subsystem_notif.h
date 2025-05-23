/* Copyright (c) 2011, 2013 - 2014, 2018 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *
 * Subsystem restart notifier API header
 *
 */

#ifndef _SUBSYS_NOTIFIER_H
#define _SUBSYS_NOTIFIER_H

#include <linux/notifier.h>

enum subsys_notif_type {
	SUBSYS_BEFORE_SHUTDOWN,
	SUBSYS_AFTER_SHUTDOWN,
	SUBSYS_BEFORE_POWERUP,
	SUBSYS_AFTER_POWERUP,
	SUBSYS_RAMDUMP_NOTIFICATION,
	SUBSYS_POWERUP_FAILURE,
	SUBSYS_PROXY_VOTE,
	SUBSYS_PROXY_UNVOTE,
	SUBSYS_SOC_RESET,
	SUBSYS_BEFORE_DS_ENTRY,
	SUBSYS_AFTER_DS_ENTRY,
	SUBSYS_DS_ENTRY_FAIL,
	SUBSYS_BEFORE_DS_EXIT,
	SUBSYS_AFTER_DS_EXIT,
	SUBSYS_DS_EXIT_FAIL,
	SUBSYS_NOTIF_TYPE_COUNT
};

enum early_subsys_notif_type {
	XPORT_LAYER_NOTIF,
	NUM_EARLY_NOTIFS
};

#if defined(CONFIG_MSM_SUBSYSTEM_RESTART)
/* Use the subsys_notif_register_notifier API to register for notifications for
 * a particular subsystem. This API will return a handle that can be used to
 * un-reg for notifications using the subsys_notif_unregister_notifier API by
 * passing in that handle as an argument.
 *
 * On receiving a notification, the second (unsigned long) argument of the
 * notifier callback will contain the notification type, and the third (void *)
 * argument will contain the handle that was returned by
 * subsys_notif_register_notifier.
 */
void *subsys_notif_register_notifier(
			const char *subsys_name, struct notifier_block *nb);
int subsys_notif_unregister_notifier(void *subsys_handle,
				struct notifier_block *nb);

/* Use the subsys_notif_init_subsys API to initialize the notifier chains form
 * a particular subsystem. This API will return a handle that can be used to
 * queue notifications using the subsys_notif_queue_notification API by passing
 * in that handle as an argument.
 */
void *subsys_notif_add_subsys(const char *subsys_name);
int subsys_notif_queue_notification(void *subsys_handle,
					enum subsys_notif_type notif_type,
					void *data);
void *subsys_get_early_notif_info(const char *subsys_name);
int subsys_register_early_notifier(const char *subsys_name,
				   enum early_subsys_notif_type notif_type,
				   void (*early_notif_cb)(void *),
				   void *data);
int subsys_unregister_early_notifier(const char *subsys_name, enum
				     early_subsys_notif_type notif_type);
void send_early_notifications(void *early_notif_handle);
#else

static inline void *subsys_notif_register_notifier(
			const char *subsys_name, struct notifier_block *nb)
{
	return NULL;
}

static inline int subsys_notif_unregister_notifier(void *subsys_handle,
					struct notifier_block *nb)
{
	return 0;
}

static inline void *subsys_notif_add_subsys(const char *subsys_name)
{
	return NULL;
}

static inline int subsys_notif_queue_notification(void *subsys_handle,
					enum subsys_notif_type notif_type,
					void *data)
{
	return 0;
}

static inline void *subsys_get_early_notif_info(const char *subsys_name)
{
	return NULL;
}

static inline int subsys_register_early_notifier(const char *subsys_name,
				   enum early_subsys_notif_type notif_type,
				   void (*early_notif_cb)(void *),
				   void *data)
{
	return -ENOTSUPP;
}

static inline int subsys_unregister_early_notifier(const char *subsys_name,
						   enum early_subsys_notif_type
						   notif_type)
{
	return -ENOTSUPP;
}

static inline void send_early_notifications(void *early_notif_handle)
{
}
#endif /* CONFIG_MSM_SUBSYSTEM_RESTART */

#endif
