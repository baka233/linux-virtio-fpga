//
// Created by baka233 on 2021/2/4.
//

#ifndef __DFL_VIRTIO_H
#define __DFL_VIRTIO_H

#define DEBUG
#include <linux/fpga-dfl.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_fpga.h>
#include <linux/types.h>
#include "dfl.h"


void virtio_fpga_ctrl_ack(struct virtqueue *vq);

struct virtio_fpga_vbuffer;
struct virtio_fpga_device;

typedef void (*virtio_fpga_resp_cb) (struct virtio_fpga_device *vfdev,
				     struct virtio_fpga_vbuffer *vbuf);


struct virtio_fpga_queue {
	struct virtqueue *vq;
	spinlock_t qlock;
	wait_queue_head_t ack_queue;
	struct work_struct dequeue_work;
};

struct virtio_fpga_port {
	int port_id;
	struct list_head node;
};

struct virtio_fpga_vbuffer
{
	char *buf;
	int size;

	void *data_buf;
	uint32_t data_size;

	char *resp_buf;
	int resp_size;
	virtio_fpga_resp_cb resp_cb;
	void *resp_cb_data;

	struct list_head list;
};

struct virtio_fpga_fme_manager {
	spinlock_t lock;

	atomic_t mmap_pending;
	uint64_t pfn;
	uint64_t num_page;
	int mmap_err;

	atomic_t munmap_pending;
	int munmap_err;

	atomic_t pr_pending;
	int pr_err;
};

struct virtio_fpga_port_manager {
	spinlock_t lock;

	atomic_t get_port_info_pending;
	struct dfl_fpga_port_info port_info;
	int get_port_info_err;

	atomic_t get_region_info_pending;
	struct dfl_fpga_port_region_info region_info;
	int get_region_info_err;

	atomic_t dma_map_pending;
	int dma_map_err;
	struct virtio_fpga_afu_resp_dma_map dma_map;

	atomic_t dma_unmap_pending;
	int dma_unmap_err;

	atomic_t mmio_map_pending;
	int mmio_map_err;
	uint64_t mmio_map_pfn;
};

struct virtio_fpga_device {
	struct device *dev;
	struct virtio_device *vdev;
	struct dfl_fpga_cdev *cdev;

	struct virtio_fpga_queue ctrlq;
	struct kmem_cache *vbufs;

	uint32_t port_num;
	uint32_t has_fme;
	atomic_t pending_commands;

	struct list_head port_list;

	wait_queue_head_t resp_wq;
	struct virtio_fpga_port_manager *port_managers;
	struct virtio_fpga_fme_manager *fme_manager;
	struct work_struct config_changed_work;
};

#define pdata_cdev_parent(pdata) ((pdata)->dfl_cdev->parent)

#define pdata_get_vdev(pdata) \
	container_of(pdata_cdev_parent((pdata)), \
		struct virtio_device, dev)

#define pdata_get_vfdev(pdata) pdata_get_vdev((pdata))->priv

#define pdata_get_port_id(pdata) ((pdata)->dev->id);


/* dfl-virtio-vq.c */
int virtio_fpga_alloc_vbufs(struct virtio_fpga_device *vfdev);
void virtio_fpga_free_vbufs(struct virtio_fpga_device *vfdev);
void virtio_fpga_init_vq(struct virtio_fpga_queue *vfvq,
			 void (*work_func)(struct work_struct *work));
void virtio_fpga_dequeue_ctrl_func(struct work_struct *work);
/* fme command */
int virtio_fpga_cmd_fme_bitstream_build(struct virtio_fpga_device *vfdev,
				       struct dfl_fpga_fme_port_pr *info);
int virtio_fpga_cmd_fme_bitstream_mmap(struct virtio_fpga_device *vfdev,
				       uint32_t port_id,
				       uint64_t length,
				       uint64_t *pfn);
int virtio_fpga_cmd_fme_bitstream_unmap(struct virtio_fpga_device *vfdev,
					uint32_t port_id);
int virtio_fpga_cmd_fme_port_reset(struct virtio_fpga_device *vfdev);
/* vafu command */
int virtio_fpga_cmd_get_port_info(struct virtio_fpga_device *vfdev,
				   uint32_t port_id,
				   struct dfl_fpga_port_info *pinfo);
int virtio_fpga_cmd_get_port_region_info(struct virtio_fpga_device *vfdev,
					  uint32_t port_id,
					  struct dfl_fpga_port_region_info *region);
int virtio_fpga_cmd_dma_map(struct virtio_fpga_device *vfdev,
			     uint32_t flags,
			     uint32_t port_id,
			     uint64_t user_addr,
			     uint64_t len,
			     uint64_t *iova);
int virtio_fpga_cmd_dma_unmap(struct virtio_fpga_device *vfev,
			       uint32_t port_id,
			       uint64_t iova);
int virtio_fpga_cmd_mmio_map(struct virtio_fpga_device *vfdev,
			     uint32_t port_id,
			     uint64_t offset,
			     uint64_t size,
			     uint64_t* pfn);


#endif // __DFL_VIRTIO_H
