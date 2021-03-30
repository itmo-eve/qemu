/*
 * Copyright (c) 2017-2018 Intel Corporation
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */

#ifndef HW_VIRTIO_VHOST_USER_H
#define HW_VIRTIO_VHOST_USER_H

#include "chardev/char-fe.h"
#include "hw/virtio/virtio.h"
#include "hw/pci/pci.h"
#include "hw/block/block.h"


typedef struct VhostUserHostNotifier {
    MemoryRegion mr;
    void *addr;
    bool set;
} VhostUserHostNotifier;

typedef struct VhostUserState {
    CharBackend *chr;
    VhostUserHostNotifier notifier[VIRTIO_QUEUE_MAX];
    int memory_slots;
} VhostUserState;

#include "hw/block/nvme.h"

bool vhost_user_init(VhostUserState *user, CharBackend *chr, Error **errp);
void vhost_user_cleanup(VhostUserState *user);

int vhost_user_nvme_admin_cmd_raw(struct vhost_dev *dev, NvmeCmd *cmd,
                                  void *buf, uint32_t len);


#endif
