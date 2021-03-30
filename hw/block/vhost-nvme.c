/*
 * QEMU NVM Express Controller
 *
 * Copyright (c) 2019, Intel Corporation
 *
 * Author:
 * Changpeng Liu <changpeng.liu@intel.com>
 *
 * This work was largely based on QEMU NVMe driver implementation by:
 * Keith Busch <keith.busch@intel.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

/**
 * Reference Specs: http://www.nvmexpress.org, 1.2, 1.1, 1.0e
 *
 *  http://www.nvmexpress.org/resources/
 */

#include "qemu/osdep.h"
#include "hw/block/block.h"
#include "hw/hw.h"
#include "sysemu/kvm.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-user.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "sysemu/sysemu.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qapi/visitor.h"
#include "nvme.h"
#include "nvme-ns.h"
#include "hw/virtio/vhost-nvme.h"


#define VHOST_NVME_BAR_READ 0
#define VHOST_NVME_BAR_WRITE 1


static int vhost_dev_nvme_start(struct vhost_dev *hdev, VirtIODevice *vdev)
{
    int r;
       /* should only be called after backend is connected */
    assert(hdev->vhost_ops);

    if (vdev != NULL) {
        return -1;
    }
    r = hdev->vhost_ops->vhost_set_mem_table(hdev, dev->mem);
    if (r < 0) {
        error_report("SET MEMTABLE Failed");
        return -1;
    }

    //vhost_user_set_u64(dev, VHOST_USER_NVME_START_STOP, 1);
    if (hdev->vhost_ops->vhost_dev_start) {
        r = hdev->vhost_ops->vhost_dev_start(hdev, true);
        if (r) {
            goto fail_log;
        }
    }

    return 0;
}

static int vhost_dev_nvme_stop(struct vhost_dev *hdev)
{
    int i;

    /* should only be called after backend is connected */
    assert(hdev->vhost_ops);

    if (hdev->vhost_ops->vhost_dev_start) {
        hdev->vhost_ops->vhost_dev_start(hdev, false);
    }

    hdev->started = false;
    hdev->vdev = NULL;
    return 0;
}

static bool nvme_nsid_valid(NvmeCtrl *n, uint32_t nsid)
{
    return nsid && (nsid == NVME_NSID_BROADCAST || nsid <= n->num_namespaces);
}

static int vhost_user_nvme_add_kvm_msi_virq(NvmeCtrl *n, NvmeCQueue *cq)
{
    int virq;
    int vector_n;

    if (!msix_enabled(&(n->parent_obj))) {
        error_report("MSIX is mandatory for the device");
        return -1;
    }

    if (event_notifier_init(&cq->guest_notifier, 0)) {
        error_report("Initiated guest notifier failed");
        return -1;
    }
    event_notifier_set_handler(&cq->guest_notifier, NULL);

    vector_n = cq->vector;

    virq = kvm_irqchip_add_msi_route(kvm_state, vector_n, &n->parent_obj);
    if (virq < 0) {
        error_report("Route MSIX vector to KVM failed");
        event_notifier_cleanup(&cq->guest_notifier);
        return -1;
    }
    cq->virq = virq;

    return 0;
}

static void vhost_user_nvme_remove_kvm_msi_virq(NvmeCQueue *cq)
{
    kvm_irqchip_release_virq(kvm_state, cq->virq);
    event_notifier_cleanup(&cq->guest_notifier);
    cq->virq = -1;
}

static void nvme_inc_cq_tail(NvmeCQueue *cq)
{
    cq->tail++;
    if (cq->tail >= cq->size) {
        cq->tail = 0;
        cq->phase = !cq->phase;
    }
}

static void nvme_inc_sq_head(NvmeSQueue *sq)
{
    sq->head = (sq->head + 1) % sq->size;
}

static uint8_t nvme_sq_empty(NvmeSQueue *sq)
{
    return sq->head == sq->tail;
}

static void nvme_isr_notify(NvmeCtrl *n, NvmeCQueue *cq)
{
    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            msix_notify(&(n->parent_obj), cq->vector);
        } else {
            pci_irq_pulse(&n->parent_obj);
        }
    }
}




static uint16_t nvme_identify_ctrl(NvmeCtrl *n, NvmeIdentify *c)
{
    uint64_t prp1 = le64_to_cpu(c->prp1);

    /* Only PRP1 used */
    pci_dma_write(&n->parent_obj, prp1, (void *)&n->id_ctrl,
                 sizeof(n->id_ctrl));
    return NVME_SUCCESS;
}

static uint16_t nvme_identify_ns(NvmeCtrl *n, NvmeIdentify *c)
{
    NvmeNamespace *ns;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    if (!nvme_nsid_valid(n, nsid) || nsid == NVME_NSID_BROADCAST) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    /* Only PRP1 used */
    ns = nvme_ns(n, nsid);
    pci_dma_write(&n->parent_obj, prp1, (void *)ns, sizeof(*ns));
    return NVME_SUCCESS;
}

static uint16_t nvme_identify(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeIdentify *c = (NvmeIdentify *)cmd;

    switch (le32_to_cpu(c->cns)) {
    case 0x00:
        return nvme_identify_ns(n, c);
    case 0x01:
        return nvme_identify_ctrl(n, c);
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
}


static void nvme_clear_guest_notifier(NvmeCtrl *n)
{
    NvmeCQueue *cq;
    uint32_t qid;

    for (qid = 1; qid <= n->num_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            break;
        }

        if (cq->irq_enabled) {
            vhost_user_nvme_remove_kvm_msi_virq(cq);
        }
    }

    if (n->vector_poll_started) {
        msix_unset_vector_notifiers(&n->parent_obj);
        n->vector_poll_started = false;
    }
}



static const char *nvme_admin_str[256] = {
    [NVME_ADM_CMD_IDENTIFY] = "NVME_ADM_CMD_IDENTIFY",
};

static uint16_t nvme_admin_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    info_report("QEMU Processing %s", nvme_admin_str[cmd->opcode] ?
            nvme_admin_str[cmd->opcode] : "Unsupported ADMIN Command");

    switch (cmd->opcode) {
    case NVME_ADM_CMD_IDENTIFY:
        return nvme_identify(n, cmd);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static int vhost_nvme_set_endpoint(NvmeCtrl *n)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct vhost_nvme_target backend;

    info_report("QEMU Start NVMe Controller ...");
    if (vhost_dev_nvme_start(&n->dev, NULL) < 0) {
        error_report("vhost_nvme_set_endpoint: vhost device start failed");
        return -1;
    }

    //NVME not have wwpn, but have serial number. See nvme_props for more info
    memset(&backend, 0, sizeof(backend));
    pstrcpy(backend.vhost_wwpn, sizeof(backend.vhost_wwpn), n->params.serial);
    ret = vhost_ops->vhost_nvme_set_endpoint(&n->dev, &backend);
    if (ret < 0) {
        return -errno;
    }

    return 0;
}

static int vhost_nvme_clear_endpoint(NvmeCtrl *n, bool shutdown)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct vhost_nvme_target backend;
    int ret;

    if (shutdown) {
        info_report("QEMU Shutdown NVMe Controller ...");
    } else {
        info_report("QEMU Disable NVMe Controller ...");
    }

    if (vhost_dev_nvme_stop(&n->dev) < 0) {
        error_report("vhost_nvme_clear_endpoint: vhost device stop failed");
        return -1;
    }

    if (shutdown) {
        nvme_clear_guest_notifier(n);
    }

    memset(&backend, 0, sizeof(backend));
    pstrcpy(backend.vhost_wwpn, sizeof(backend.vhost_wwpn), n->params.serial);
    ret = vhost_ops->vhost_nvme_clear_endpoint(&n->dev, &backend);
    if (ret < 0) {
        return -errno;
    }

    n->bar.cc = 0;
    n->dataplane_started = false;
    return 0;
}

static void nvme_write_bar(NvmeCtrl *n, hwaddr offset, uint64_t data,
                           unsigned size)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct nvmet_vhost_bar nvmet_bar;
    int ret;

    memset(&nvmet_bar, 0, sizeof(nvmet_bar));
    nvmet_bar.type = VHOST_NVME_BAR_WRITE;
    nvmet_bar.offset = offset;
    nvmet_bar.size = size;
    nvmet_bar.val = data;
    ret = vhost_ops->vhost_nvme_bar(&n->dev, &nvmet_bar);
    if (ret < 0) {
        error_report("nvme_write_bar error = %d", ret);
    }

}

static uint64_t nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    uint8_t *ptr = (uint8_t *)&n->bar;
    uint64_t val = 0;
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct nvmet_vhost_bar nvmet_bar;
    int ret;

    if (unlikely(addr & (sizeof(uint32_t) - 1))) {
        error_report("MMIO read not 32-bit aligned, offset=0x%"PRIx64"", addr);
        // should RAZ, fall through for now
    } else if (unlikely(size < sizeof(uint32_t))) {
        error_report("MMIO read smaller than 32-bits,"
                     " offset=0x%"PRIx64"", addr);
        // should RAZ, fall through for now
    }
    memset(&nvmet_bar, 0, sizeof(nvmet_bar));
    nvmet_bar.type = VHOST_NVME_BAR_READ;
    nvmet_bar.offset = addr;
    nvmet_bar.size = size;
    val = vhost_ops->vhost_nvme_bar(&n->dev, &nvmet_bar);
    if (ret < 0) {
        error_report("nvme_write_bar error = %d", ret);
    }

    return val;
}

static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    if (addr < sizeof(n->bar)) {
        nvme_write_bar(n, addr, data, size);
    }
}

static const MemoryRegionOps nvme_mmio_ops = {
    .read = nvme_mmio_read,
    .write = nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static void nvme_cleanup(NvmeCtrl *n)
{
    g_free(n->sq);
    g_free(n->cq);
    g_free(n->namespaces);
}

static void nvme_check_constraints(NvmeCtrl *n, Error **errp)
{
    NvmeParams *params = &n->params;

    if (!params->serial) {
        error_setg(errp, "serial property not set");
        return;
    }
}

static void nvme_realize(PCIDevice *pci_dev, Error **errp)
{
    NvmeCtrl *n = NVME_VHOST(pci_dev);
    NvmeIdCtrl *id = &n->id_ctrl;
    NvmeNamespace *ns;
    NvmeIdentify cmd;
    int ret, i;
    int vhostfd = -1;
    uint8_t *pci_conf;
    uint64_t bar_cap;
    Error *local_err = NULL;

    nvme_check_constraints(n, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    if (n->params.vhostfd) {
        vhostfd = monitor_fd_param(monitor_cur(), n->params.vhostfd, errp);
        if (vhostfd == -1) {
            error_prepend(errp, "vhost-scsi: unable to parse vhostfd: ");
            return;
        }
    } else {
        vhostfd = open("/dev/vhost-nvme", O_RDWR);
        if (vhostfd < 0) {
            error_setg(errp, "vhost-scsi: open vhost char device failed: %s",
                       strerror(errno));
            return;
        }
    }

    if (vhost_dev_nvme_init(&n->dev, (void *)vhostfd,
                            VHOST_BACKEND_TYPE_KERNEL, 0) < 0) {
        error_setg(errp, "vhost-user-nvme: vhost_dev_init failed");
        return;
    }

    n->reg_size = pow2ceil(0x1004 + 2 * (n->num_io_queues + 2) * 4);

    /* nvme_init_state */
    n->sq = g_new0(NvmeSQueue *, n->num_io_queues + 1);
    n->cq = g_new0(NvmeCQueue *, n->num_io_queues + 1);
    assert(n->sq != NULL);
    assert(n->cq != NULL);

    /* nvme_init_pci */
    pci_conf = pci_dev->config;
    pci_conf[PCI_INTERRUPT_PIN] = 1;
    pci_config_set_prog_interface(pci_dev->config, 0x2);
    pci_config_set_class(pci_dev->config, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(&n->parent_obj, 0x80);

    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n,
                          "nvme", n->reg_size);

    pci_register_bar(&n->parent_obj, 0,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
        &n->iomem);
    msix_init_exclusive_bar(&n->parent_obj, n->num_io_queues, 4, NULL);

    ret = vhost_nvme_set_endpoint(n);
    if (ret < 0) {
        error_setg(errp, "vhost-nvme: set endpoint ioctl failed");
        return;
    }

    /* setup a namespace if the controller drive property was given */
    if (n->namespace.blkconf.blk) {
        ns = &n->namespace;
        ns->params.nsid = 1;

        if (nvme_ns_setup(n, ns, errp)) {
            return;
        }
    }
    return;

err:
    nvme_cleanup(n);
}

static void nvme_exit(PCIDevice *pci_dev)
{
    NvmeCtrl *n = NVME_VHOST(pci_dev);

    vhost_nvme_clear_endpoint(n, 1);
    nvme_cleanup(n);
    msix_uninit_exclusive_bar(pci_dev);
}

static Property nvme_props[] = {//char *vhostfd;
    DEFINE_PROP_STRING("vhostfd", NvmeCtrl, params.vhostfd),
    DEFINE_PROP_STRING("serial", NvmeCtrl, params.serial),
    DEFINE_PROP_UINT32("num_io_queues", NvmeCtrl, num_io_queues, 1),
    DEFINE_PROP_LINK("barmem", NvmeCtrl, barmem, TYPE_MEMORY_BACKEND, HostMemoryBackend *),
    DEFINE_PROP_CHR("chardev", NvmeCtrl, chardev),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription nvme_vmstate = {
    .name = "nvme",
    .unmigratable = 1,
};

static void nvme_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->realize = nvme_realize;
    pc->exit = nvme_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0x5845;
    pc->revision = 2;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Non-Volatile Memory Express";
    device_class_set_props(dc, nvme_props);
    dc->vmsd = &nvme_vmstate;
}

static void nvme_instance_init(Object *obj)
{
    NvmeCtrl *s = NVME_VHOST(obj);

    device_add_bootindex_property(obj, &s->bootindex,
                                  "bootindex", "/namespace@1,0",
                                  DEVICE(obj));
}

static const TypeInfo nvme_info = {
    .name          = "vhost-kernel-nvme",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(NvmeCtrl),
    .class_init    = nvme_class_init,
    .instance_init = nvme_instance_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    },
};

static void nvme_register_types(void)
{
    type_register_static(&nvme_info);
}

type_init(nvme_register_types)
