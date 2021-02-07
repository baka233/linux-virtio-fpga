//
// Created by baka233 on 2021/2/4.
//

#ifndef __DFL_VIRTIO_H
#define __DFL_VIRTIO_H


#include <linux/fpga-dfl.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/fpga-dfl.h>
#include <linux/virtio_fpga.h>
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

struct virtio_fpag_port {
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

struct virtio_fpga_device {
	struct device *dev;
	struct virtio_device *vdev;
	struct dfl_fpga_cdev *cdev;

	struct virtio_fpga_queue ctrlq;
	struct kmem_cache *vbufs;

	uint32_t port_num;

	struct list_head port_list;

	wait_queue_head_t resp_wq;
	struct work_struct config_changed_work;
};


/* dfl-virtio-vq.c */
int virtio_fpga_alloc_vbufs(struct virtio_fpga_device *vfdev);
void virtio_fpga_free_vbufs(struct virtio_fpga_device *vfdev);
void virtio_fpga_init_vq(struct virtio_fpga_queue *vfvq,
			 void (*work_func)(struct work_struct *work));
void virtio_fpga_dequeue_ctrl_func(struct work_struct *work);
/* fme command */
void virtio_fpga_cmd_fme_port_pr(struct virtio_fpga_device *vfdev,
				 uint32_t port_id,
				 uint32_t flags,
				 void* base_addr,
				 int size);
void virtio_fpga_cmd_fme_port_reset(struct virtio_fpga_device *vfdev);
/* vafu command */
void virtio_fpga_cmd_get_port_info(struct virtio_fpga_device *vfdev,
				   uint32_t port_id);
void virtio_fpga_cmd_get_port_region_info(struct virtio_fpga_device *vfdev,
					  uint32_t port_id);
void virtio_fpga_cmd_dma_map(struct virtio_fpga_device *vfdev,
			     uint32_t port_id);
void virtio_fpga_cmd_dma_unmap(struct virtio_fpga_device *vfev,
			       uint32_t port_id);
void virtio_fpga_cmd_mmio_map(struct virtio_fpga_device *vfdev,
			      uint32_t port_id);


#endif // __DFL_VIRTIO_H
