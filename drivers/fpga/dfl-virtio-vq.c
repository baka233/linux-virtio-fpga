//
// Created by baka233 on 2021/2/5.
//
#include "dfl-virtio.h"

#define MAX_INLINE_CMD_SIZE 96
#define MAX_INLINE_RESP_SIZE 24
#define VBUFFER_SIZE	(sizeof(struct virtio_fpga_vbuffer) \
			+ MAX_INLINE_CMD_SIZE               \
			+ MAX_INLINE_RESP_SIZE)

void virtio_fpga_ctrl_ack(struct virtqueue *vq)
{
	struct virtio_fpga_device *vfdev = vq->vdev->priv;

	schedule_work(&vfdev->ctrlq.dequeue_work);
}

static struct virtio_fpga_ctrl_hdr *
virtio_fpga_vbuf_ctrl_hdr(struct virtio_fpga_vbuffer *vbuf)
{
	/* this assumes a vbuf contains a command that starts with a
	 * virtio_fpga_ctrl_hdr, which is true for both ctrl and cursor
	 * virtqueues.
	 */
	return (struct virtio_fpga_ctrl_hdr *)vbuf->buf;
}

int virtio_fpga_alloc_vbufs(struct virtio_fpga_device *vfdev)
{
	vfdev->vbufs = kmem_cache_create("virtio-fpga-vbufs",
					 VBUFFER_SIZE,
					 __alignof__(struct virtio_fpga_vbuffer),
					 0, NULL);

	if (!vfdev->vbufs)
		return -ENOMEM;
	return 0;
}

static void free_vbuf(struct virtio_fpga_device *vfdev,
		      struct virtio_fpga_vbuffer *vbuf)
{
	if (vbuf->resp_size > MAX_INLINE_RESP_SIZE)
		kfree(vbuf->resp_buf);
	kvfree(vbuf->data_buf);
	kmem_cache_free(vfdev->vbufs, vbuf);
}

void virtio_fpga_init_vq(struct virtio_fpga_queue *vfvq,
				void (*work_func)(struct work_struct *work))
{
	spin_lock_init(&vfvq->qlock);
	init_waitqueue_head(&vfvq->ack_queue);
	INIT_WORK(&vfvq->dequeue_work, work_func);
}

static void reclaim_vbufs(struct virtqueue *vq, struct list_head *reclaim_list)
{
	struct virtio_fpga_vbuffer *vbuf;
	unsigned int len;
	int freed = 0;

	while ((vbuf = virtqueue_get_buf(vq, &len))) {
		list_add_tail(&vbuf->list, reclaim_list);
		freed++;
	}
	if (freed == 0)
		printk(KERN_DEBUG "dfl-virtio: Huh? zero vbufs reclaimed");
}

void virtio_fpga_dequeue_ctrl_func(struct work_struct *work)
{
	struct virtio_fpga_device *vfdev =
		container_of(work, struct virtio_fpga_device,
			     ctrlq.dequeue_work);
	struct list_head reclaim_list;
	struct virtio_fpga_ctrl_hdr *resp;
	struct virtio_fpga_vbuffer *entry, *tmp;

	INIT_LIST_HEAD(&reclaim_list);
	spin_lock(&vfdev->ctrlq.qlock);
	// reclaim resp buffser from vq
	do {
		virtqueue_disable_cb(vfdev->ctrlq.vq);
		reclaim_vbufs(vfdev->ctrlq.vq, &reclaim_list);

	} while (!virtqueue_enable_cb(vfdev->ctrlq.vq));
	spin_unlock(&vfdev->ctrlq.qlock);

	list_for_each_entry(entry, &reclaim_list, list) {
		resp = (struct virtio_fpga_ctrl_hdr *)entry->resp_buf;

		// trace_virtio_fpga_cmd_response(vfdev->ctrlq.vq, resp);
		if (resp->type >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
			struct virtio_fpga_ctrl_hdr *cmd;
			cmd = virtio_fpga_vbuf_ctrl_hdr(entry);
			printk(KERN_ERR "response 0x%x (command 0x%x)\n",
				le32_to_cpu(resp->type),
				le32_to_cpu(cmd->type));
		} else
			printk(KERN_ERR "response 0x%x\n", le32_to_cpu(resp->type));
	}
	if (entry->resp_cb)
		entry->resp_cb(vfdev, entry);
	wake_up(&vfdev->ctrlq.ack_queue);

	list_for_each_entry_safe(entry, tmp, &reclaim_list, list) {
		list_del(&entry->list);
		free_vbuf(vfdev, entry);
	}
}