//
// Created by baka233 on 2021/2/5.
//
#include "dfl-virtio.h"
#include <linux/byteorder/generic.h>

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

static struct virtio_fpga_vbuffer*
virtio_fpga_get_vbuf(struct virtio_fpga_device *vfdev,
		    int size, int resp_size, void *resp_buf,
		    virtio_fpga_resp_cb resp_cb)
{
	struct virtio_fpga_vbuffer *vbuf;

	vbuf = kmem_cache_zalloc(vfdev->vbufs, GFP_KERNEL);
	if (!vbuf)
		return ERR_PTR(-ENOMEM);

	BUG_ON(size > MAX_INLINE_CMD_SIZE ||
	       size < sizeof(struct virtio_fpga_ctrl_hdr));
	vbuf->buf = (void *)vbuf + sizeof(*vbuf);
	vbuf->size = size;

	vbuf->resp_cb = resp_cb;
	vbuf->resp_size = resp_size;
	if (resp_size <= MAX_INLINE_RESP_SIZE)
		vbuf->resp_buf = (void *)vbuf->buf + size;
	else
		vbuf->resp_buf = resp_buf;
	BUG_ON(!vbuf->resp_buf);
	return vbuf;
}

void virtio_fpga_notify(struct virtio_fpga_device *vfdev)
{
	bool notify;

	if (!atomic_read(&vfdev->pending_commands))
		return;

	spin_lock(&vfdev->ctrlq.qlock);
	atomic_set(&vfdev->pending_commands, 0);
	notify = virtqueue_kick_prepare(vfdev->ctrlq.vq);
	spin_unlock(&vfdev->ctrlq.qlock);

	if (notify)
		virtqueue_notify(vfdev->ctrlq.vq);
}


static void *virtio_fpga_alloc_cmd_resp(struct virtio_fpga_device *vfdev,
				       virtio_fpga_resp_cb cb,
				       struct virtio_fpga_vbuffer **vbuffer_p,
				       int cmd_size, int resp_size,
				       void *resp_buf)
{
	struct virtio_fpga_vbuffer *vbuf;

	vbuf = virtio_fpga_get_vbuf(vfdev, cmd_size,
				   resp_size, resp_buf, cb);
	if (IS_ERR(vbuf)) {
		*vbuffer_p = NULL;
		return ERR_CAST(vbuf);
	}
	*vbuffer_p = vbuf;
	return (struct virtio_fpga_command *)vbuf->buf;
}

static void *virtio_fpga_alloc_cmd(struct virtio_fpga_device *vfdev,
				  struct virtio_fpga_vbuffer **vbuffer_p,
				  int size)
{
	return virtio_fpga_alloc_cmd_resp(vfdev, NULL, vbuffer_p, size,
					 sizeof(struct virtio_fpga_ctrl_hdr),
					 NULL);
}

static void *virtio_fpga_alloc_cmd_cb(struct virtio_fpga_device *vfdev,
				     struct virtio_fpga_vbuffer **vbuffer_p,
				     int size,
				     virtio_fpga_resp_cb cb)
{
	return virtio_fpga_alloc_cmd_resp(vfdev, cb, vbuffer_p, size,
					 sizeof(struct virtio_fpga_ctrl_hdr),
					 NULL);
}

static int virtio_fpga_queue_ctrl_sgs(struct virtio_fpga_device *vfdev,
				      struct virtio_fpga_vbuffer *vbuf,
				      int elemcnt,
				      struct scatterlist **sgs,
				      int outcnt,
				      int incnt)
{
	struct virtqueue *vq = vfdev->ctrlq.vq;
	int ret;

again:
	spin_lock(&vfdev->ctrlq.qlock);

	if (vq->num_free < elemcnt) {
		spin_unlock(&vfdev->ctrlq.qlock);
		virtio_fpga_notify(vfdev);
		wait_event(vfdev->ctrlq.ack_queue, vq->num_free >= elemcnt);
		goto again;
	}

	ret = virtqueue_add_sgs(vq, sgs, outcnt, incnt, vbuf, GFP_ATOMIC);
	WARN_ON(ret);

	atomic_inc(&vfdev->pending_commands);

	spin_unlock(&vfdev->ctrlq.qlock);
	return 0;
}

static int virtio_fpga_queue_ctrl_buffer(struct virtio_fpga_device *vfdev,
					 struct virtio_fpga_vbuffer *vbuf)
{
	struct scatterlist *sgs[3], vcmd, vresp;
	struct sg_table *sgt = NULL;
	int elemcnt = 0, outcnt = 0, incnt = 0, ret;

	/* set up vcmd */
	sg_init_one(&vcmd, vbuf->buf, vbuf->size);
	elemcnt++;
	sgs[outcnt] = &vcmd;
	outcnt++;

	if (vbuf->resp_size) {
		sg_init_one(&vresp, vbuf->resp_buf, vbuf->resp_size);
		elemcnt++;
		sgs[outcnt + incnt] = &vresp;
		incnt++;
	}

	ret = virtio_fpga_queue_ctrl_sgs(vfdev, vbuf, elemcnt, sgs, outcnt, incnt);

	if (sgt) {
		sg_free_table(sgt);
		kfree(sgt);
	}
	return ret;
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
		if (le32_to_cpu(resp->type) >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
			struct virtio_fpga_ctrl_hdr *cmd;
			cmd = virtio_fpga_vbuf_ctrl_hdr(entry);
			printk(KERN_ERR "response 0x%x (command 0x%x)\n",
				le32_to_cpu(resp->type),
				le32_to_cpu(cmd->type));
		} else
			printk(KERN_ERR "response 0x%x\n", le32_to_cpu(resp->type));

		if (entry->resp_cb) {
			entry->resp_cb(vfdev, entry);
		}
	}
	wake_up(&vfdev->ctrlq.ack_queue);
	dev_dbg(vfdev->dev, "process queue successfully");

	list_for_each_entry_safe(entry, tmp, &reclaim_list, list) {
		list_del(&entry->list);
		free_vbuf(vfdev, entry);
	}
}

/* vafu cmd process */

static void virtio_fpga_cmd_get_port_info_cb(struct virtio_fpga_device *vfdev,
				      struct virtio_fpga_vbuffer *vbuf)
{
	struct virtio_fpga_afu_resp_port_info *resp =
		(struct virtio_fpga_afu_resp_port_info*)vbuf->resp_buf;
	uint32_t port_id = le32_to_cpu(resp->hdr.port_id);
	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	spin_lock(&port_manager->lock);

	atomic_set(&port_manager->get_port_info_pending, 0);

	if (resp->hdr.type >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
		port_manager->get_port_info_err = -EINVAL;
		spin_unlock(&port_manager->lock);
		printk(KERN_ERR "dfl-virtio: get dfl port failed");
		wake_up(&vfdev->resp_wq);
		return;
	}

	port_manager->port_info.num_regions = le64_to_cpu(resp->num_regions);
	port_manager->port_info.num_umsgs = le64_to_cpu(resp->num_umsgs);
	port_manager->port_info.flags = le64_to_cpu(resp->flags);

	printk(KERN_DEBUG "dfl-virtio: num_regions: %d, num_umsgs: %d, flags: %d",
	       resp->num_regions,
	       resp->num_umsgs,
	       resp->flags);
	wake_up(&vfdev->resp_wq);
	spin_unlock(&port_manager->lock);
}

int virtio_fpga_cmd_get_port_info(struct virtio_fpga_device *vfdev,
				  uint32_t port_id,
				  struct dfl_fpga_port_info *pinfo)
{
	struct virtio_fpga_afu_port_info *cmd_p;
	struct virtio_fpga_vbuffer *vbuf;
	void* resp_buf;
	int ret;

	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	resp_buf = kzalloc(sizeof(struct virtio_fpga_afu_resp_port_info),
			   GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	cmd_p = virtio_fpga_alloc_cmd_resp(vfdev,
				       virtio_fpga_cmd_get_port_info_cb,
				       &vbuf,
				       sizeof(*cmd_p),
				       sizeof(struct virtio_fpga_afu_resp_port_info),
				       resp_buf);
	memset(cmd_p, 0, sizeof(*cmd_p));

	spin_lock(&port_manager->lock);
	atomic_set(&port_manager->get_port_info_pending, 1);
	port_manager->get_port_info_err = 0;
	spin_unlock(&port_manager->lock);

	cmd_p->hdr.type = cpu_to_le32(VIRTIO_FPGA_CMD_GET_PORT_INFO);
	cmd_p->hdr.port_id = cpu_to_le32(port_id);
	cmd_p->hdr.is_fme = cpu_to_le32(false);

	virtio_fpga_queue_ctrl_buffer(vfdev, vbuf);


	virtio_fpga_notify(vfdev);
	ret = wait_event_timeout(vfdev->resp_wq,
			 	!atomic_read(&port_manager->get_port_info_pending),
			 	5 * HZ);

	if (!ret) {
		return -EBUSY;
	}

	spin_lock(&port_manager->lock);

	if (port_manager->get_port_info_err) {
		int err = port_manager->get_port_info_err;
		spin_unlock(&port_manager->lock);
		return err;
	}

	dev_dbg(vfdev->dev, "get port info successfully");

	pinfo->flags = port_manager->port_info.flags;
	pinfo->num_regions = port_manager->port_info.num_regions;
	pinfo->num_umsgs = port_manager->port_info.num_umsgs;

	dev_dbg(vfdev->dev, "flags: 0x%x, num_regions: %d, num_umsgs: %d", pinfo->flags, pinfo->num_regions, pinfo->num_umsgs);

	spin_unlock(&port_manager->lock);

	return 0;
}

static void virtio_fpga_cmd_get_port_region_info_cb(struct virtio_fpga_device *vfdev,
					     struct virtio_fpga_vbuffer *vbuf)
{
	struct virtio_fpga_afu_resp_region_info *resp =
		(struct virtio_fpga_afu_resp_region_info*)vbuf->resp_buf;
	uint32_t port_id = le32_to_cpu(resp->hdr.port_id);
	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	spin_lock(&port_manager->lock);

	atomic_set(&port_manager->get_region_info_pending, 0);

	if (resp->hdr.type >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
		port_manager->get_region_info_err = -EINVAL;
		spin_unlock(&port_manager->lock);
		printk(KERN_ERR "dfl-virtio: get dfl region info failed");
		wake_up(&vfdev->resp_wq);
		return;
	}

	port_manager->region_info.size = le64_to_cpu(resp->size);
	port_manager->region_info.offset = le64_to_cpu(resp->offset);
	port_manager->region_info.flags = le64_to_cpu(resp->flags);

	printk(KERN_DEBUG "dfl-virtio: size: %lld, offset: %lld, flags: %d",
		resp->size,
		resp->offset,
		resp->flags);

	wake_up(&vfdev->resp_wq);
	spin_unlock(&port_manager->lock);
}

int virtio_fpga_cmd_get_port_region_info(struct virtio_fpga_device *vfdev,
					 uint32_t port_id,
					 struct dfl_fpga_port_region_info *rinfo)
{
	struct virtio_fpga_afu_region_info *cmd_p;
	struct virtio_fpga_vbuffer *vbuf;
	void* resp_buf;
	int ret;

	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	resp_buf = kzalloc(sizeof(struct virtio_fpga_afu_resp_region_info),
			   GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	cmd_p = virtio_fpga_alloc_cmd_resp(vfdev,
				       virtio_fpga_cmd_get_port_region_info_cb,
				       &vbuf,
				       sizeof(*cmd_p),
				       sizeof(struct virtio_fpga_afu_resp_region_info),
				       resp_buf);
	memset(cmd_p, 0, sizeof(*cmd_p));

	cmd_p->hdr.type = cpu_to_le32(VIRTIO_FPGA_CMD_GET_PORT_REGION_INFO);
	cmd_p->hdr.port_id = cpu_to_le32(port_id);
	cmd_p->hdr.is_fme = cpu_to_le32(false);

	cmd_p->index = cpu_to_le32(rinfo->index);

	spin_lock(&port_manager->lock);
	atomic_set(&port_manager->get_region_info_pending, 1);
	port_manager->get_region_info_err = 0;
	spin_unlock(&port_manager->lock);

	virtio_fpga_queue_ctrl_buffer(vfdev, vbuf);

	virtio_fpga_notify(vfdev);
	ret = wait_event_timeout(vfdev->resp_wq,
				 !atomic_read(&port_manager->get_region_info_pending),
				 5 * HZ);

	spin_lock(&port_manager->lock);
	if (port_manager->get_region_info_err) {
		int err = port_manager->get_region_info_err;
		spin_unlock(&port_manager->lock);
		return err;
	}

	rinfo->flags = port_manager->region_info.flags;
	rinfo->size = port_manager->region_info.size;
	rinfo->offset = port_manager->region_info.offset;

	spin_unlock(&port_manager->lock);

	return 0;
}

void virtio_fpga_cmd_dma_map_cb(struct virtio_fpga_device *vfdev,
				struct virtio_fpga_vbuffer *vbuf)
{
	struct virtio_fpga_afu_resp_dma_map *resp =
		(struct virtio_fpga_afu_resp_dma_map*)vbuf->resp_buf;
	uint32_t port_id = le32_to_cpu(resp->hdr.port_id);
	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	spin_lock(&port_manager->lock);

	atomic_set(&port_manager->dma_map_pending, 0);

	if (resp->hdr.type >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
		port_manager->dma_map_err = -EINVAL;
		spin_unlock(&port_manager->lock);
		printk(KERN_ERR "dfl-virtio: map dma region info failed");
		wake_up(&vfdev->resp_wq);
		return;
	}

	port_manager->dma_map.pfn = resp->pfn;
	port_manager->dma_map.iova = resp->iova;
	port_manager->dma_map.num_page = resp->num_page;

	printk(KERN_DEBUG "dfl-virtio: pfn: 0x%16llx, iova: %16llx, num_pages: %lld",
		resp->pfn,
		resp->iova,
		resp->num_page);

	wake_up(&vfdev->resp_wq);
	spin_unlock(&port_manager->lock);
}

int virtio_fpga_cmd_dma_map(struct virtio_fpga_device *vfdev,
			    uint32_t flags,
			    uint32_t port_id,
			    uint64_t user_addr,
			    uint64_t len,
			    uint64_t *iova)
{
	struct virtio_fpga_afu_dma_map *cmd_p;
	struct virtio_fpga_vbuffer *vbuf;
	void* resp_buf;
	int ret;

	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	resp_buf = kzalloc(sizeof(struct virtio_fpga_afu_resp_dma_map),
			   GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	cmd_p = virtio_fpga_alloc_cmd_resp(vfdev,
					   virtio_fpga_cmd_dma_map_cb,
					   &vbuf,
					   sizeof(*cmd_p),
					   sizeof(struct virtio_fpga_afu_resp_dma_map),
					   resp_buf);
	memset(cmd_p, 0, sizeof(*cmd_p));

	cmd_p->hdr.type = cpu_to_le32(VIRTIO_FPGA_CMD_DMA_MAP);
	cmd_p->hdr.port_id = cpu_to_le32(port_id);
	cmd_p->hdr.is_fme = cpu_to_le32(false);

	cmd_p->flags = flags;
	cmd_p->length = len;

	spin_lock(&port_manager->lock);
	atomic_set(&port_manager->dma_map_pending, 1);
	port_manager->dma_map_err = 0;
	spin_unlock(&port_manager->lock);

	virtio_fpga_queue_ctrl_buffer(vfdev, vbuf);

	virtio_fpga_notify(vfdev);
	ret = wait_event_timeout(vfdev->resp_wq,
				 !atomic_read(&port_manager->dma_map_pending),
				 5 * HZ);

	spin_lock(&port_manager->lock);
	if (port_manager->dma_map_err) {
		int err = port_manager->dma_map_err;
		spin_unlock(&port_manager->lock);
		return err;
	}

	*iova = le64_to_cpu(port_manager->dma_map.iova);
	uint64_t pfn = le64_to_cpu(port_manager->dma_map.pfn);
	uint64_t num_page = le64_to_cpu(port_manager->dma_map.num_page);

	struct vm_area_struct* vma = find_vma(current->mm, user_addr);
	if (vma == NULL) {
		return -EINVAL;
	}

	struct mm_struct* mm = vma->vm_mm;

	dev_dbg(vfdev->dev, "vma->start is 0x%0lx", vma->vm_start);

	mmap_write_lock(mm);
	ret = remap_pfn_range(vma, vma->vm_start,
			pfn,
			len, vma->vm_page_prot);
	mmap_write_unlock(mm);
	if (ret != 0) {
		return ret;
	}

	spin_unlock(&port_manager->lock);

	return 0;
}

static void virtio_fpga_cmd_dma_unmap_cb(struct virtio_fpga_device *vfdev,
				  struct virtio_fpga_vbuffer *vbuf)
{
	struct virtio_fpga_ctrl_hdr *hdr =
		(struct virtio_fpga_ctrl_hdr*)vbuf->resp_buf;
	uint32_t port_id = le32_to_cpu(hdr->port_id);
	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	spin_lock(&port_manager->lock);

	atomic_set(&port_manager->dma_unmap_pending, 0);

	if (hdr->type >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
		port_manager->dma_unmap_err = -EINVAL;
		spin_unlock(&port_manager->lock);
		printk(KERN_ERR "dfl-virtio: unmap dma region failed");
		wake_up(&vfdev->resp_wq);
		return;
	}

	wake_up(&vfdev->resp_wq);
	spin_unlock(&port_manager->lock);
}

int virtio_fpga_cmd_dma_unmap(struct virtio_fpga_device *vfdev,
			      uint32_t port_id,
			      uint64_t iova)
{
	struct virtio_fpga_afu_dma_unmap *cmd_p;
	struct virtio_fpga_vbuffer *vbuf;
	void* resp_buf;
	int ret;

	resp_buf = kzalloc(sizeof(struct virtio_fpga_ctrl_hdr),
			   GFP_KERNEL);

	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	cmd_p = virtio_fpga_alloc_cmd_resp(vfdev,
					   virtio_fpga_cmd_dma_unmap_cb,
					   &vbuf,
					   sizeof(*cmd_p),
					   sizeof(struct virtio_fpga_ctrl_hdr),
					   resp_buf);
	memset(cmd_p, 0, sizeof(*cmd_p));

	cmd_p->hdr.type = cpu_to_le32(VIRTIO_FPGA_CMD_DMA_UNMAP);
	cmd_p->hdr.port_id = cpu_to_le32(port_id);
	cmd_p->hdr.is_fme = cpu_to_le32(false);

	cmd_p->iova = cpu_to_le64(iova);

	spin_lock(&port_manager->lock);
	atomic_set(&port_manager->dma_unmap_pending, 1);
	port_manager->dma_unmap_err = 0;
	spin_unlock(&port_manager->lock);

	virtio_fpga_queue_ctrl_buffer(vfdev, vbuf);

	virtio_fpga_notify(vfdev);
	ret = wait_event_timeout(vfdev->resp_wq,
				 !atomic_read(&port_manager->dma_unmap_pending),
				 5 * HZ);

	spin_lock(&port_manager->lock);
	if (port_manager->dma_unmap_err) {
		int err = port_manager->dma_unmap_err;
		spin_unlock(&port_manager->lock);
		return err;
	}

	spin_unlock(&port_manager->lock);

	return 0;
}


static void virtio_fpga_cmd_mmio_map_cb(struct virtio_fpga_device *vfdev,
				struct virtio_fpga_vbuffer *vbuf)
{
	struct virtio_fpga_afu_resp_mmio_map *resp =
		(struct virtio_fpga_afu_resp_mmio_map*)vbuf->resp_buf;
	uint32_t port_id = le32_to_cpu(resp->hdr.port_id);
	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	spin_lock(&port_manager->lock);

	atomic_set(&port_manager->mmio_map_pending, 0);

	if (resp->hdr.type >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
		port_manager->mmio_map_err = -EINVAL;
		spin_unlock(&port_manager->lock);
		printk(KERN_ERR "dfl-virtio: map mmio region info failed");
		wake_up(&vfdev->resp_wq);
		return;
	}

	port_manager->mmio_map_pfn = le64_to_cpu(resp->pfn);

	printk(KERN_DEBUG "dfl-virtio: mmio_map, pfn: 0x%16llx", port_manager->mmio_map_pfn);

	wake_up(&vfdev->resp_wq);
	spin_unlock(&port_manager->lock);
}

int virtio_fpga_cmd_mmio_map(struct virtio_fpga_device *vfdev,
			     uint32_t port_id,
			     uint64_t offset,
			     uint64_t size,
			     uint32_t flags,
			     uint64_t* pfn)
{
	struct virtio_fpga_afu_mmio_map *cmd_p;
	struct virtio_fpga_vbuffer *vbuf;
	void* resp_buf;
	int ret;

	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	resp_buf = kzalloc(sizeof(struct virtio_fpga_afu_resp_mmio_map),
			   GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	cmd_p = virtio_fpga_alloc_cmd_resp(vfdev,
					   virtio_fpga_cmd_mmio_map_cb,
					   &vbuf,
					   sizeof(*cmd_p),
					   sizeof(struct virtio_fpga_afu_resp_mmio_map),
					   resp_buf);
	memset(cmd_p, 0, sizeof(*cmd_p));

	cmd_p->hdr.type = cpu_to_le32(VIRTIO_FPGA_CMD_MMIO_MAP);
	cmd_p->hdr.port_id = cpu_to_le32(port_id);
	cmd_p->hdr.is_fme = cpu_to_le32(false);

	cmd_p->offset = cpu_to_le64(offset);
	cmd_p->size = cpu_to_le64(size);
	cmd_p->flags = cpu_to_le32(flags);

	spin_lock(&port_manager->lock);
	atomic_set(&port_manager->mmio_map_pending, 1);
	port_manager->mmio_map_err = 0;
	spin_unlock(&port_manager->lock);

	virtio_fpga_queue_ctrl_buffer(vfdev, vbuf);

	virtio_fpga_notify(vfdev);
	ret = wait_event_timeout(vfdev->resp_wq,
				 !atomic_read(&port_manager->mmio_map_pending),
				 5 * HZ);

	spin_lock(&port_manager->lock);
	if (port_manager->mmio_map_err) {
		int err = port_manager->mmio_map_err;
		spin_unlock(&port_manager->lock);
		return err;
	}

	*pfn = le64_to_cpu(port_manager->mmio_map_pfn);
	spin_unlock(&port_manager->lock);

	return 0;
}


static void virtio_fpga_afu_reset_cb(struct virtio_fpga_device *vfdev,
					struct virtio_fpga_vbuffer *vbuf)
{
	struct virtio_fpga_ctrl_hdr *resp =
		(struct virtio_fpga_ctrl_hdr*)vbuf->resp_buf;
	uint32_t port_id = le32_to_cpu(resp->port_id);
	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	spin_lock(&port_manager->lock);

	atomic_set(&port_manager->afu_reset_pending, 0);

	if (resp->type >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
		port_manager->afu_reset_err = -EINVAL;
		spin_unlock(&port_manager->lock);
		printk(KERN_ERR "dfl-virtio: afu reset failed");
		wake_up(&vfdev->resp_wq);
		return;
	}

	wake_up(&vfdev->resp_wq);
	spin_unlock(&port_manager->lock);
}

int virtio_fpga_cmd_afu_reset(struct virtio_fpga_device *vfdev,
			     uint32_t port_id)
{
	struct virtio_fpga_ctrl_hdr *cmd_p;
	struct virtio_fpga_vbuffer *vbuf;
	void* resp_buf;
	int ret;

	struct virtio_fpga_port_manager *port_manager = &vfdev->port_managers[port_id];

	resp_buf = kzalloc(sizeof(struct virtio_fpga_ctrl_hdr),
			   GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	cmd_p = virtio_fpga_alloc_cmd_resp(vfdev,
					   virtio_fpga_afu_reset_cb,
					   &vbuf,
					   sizeof(*cmd_p),
					   sizeof(struct virtio_fpga_ctrl_hdr),
					   resp_buf);
	memset(cmd_p, 0, sizeof(*cmd_p));

	cmd_p->type = cpu_to_le32(VIRTIO_FPGA_CMD_AFU_RESET);
	cmd_p->port_id = cpu_to_le32(port_id);
	cmd_p->is_fme = cpu_to_le32(false);

	spin_lock(&port_manager->lock);
	atomic_set(&port_manager->afu_reset_pending, 1);
	port_manager->afu_reset_err = 0;
	spin_unlock(&port_manager->lock);

	virtio_fpga_queue_ctrl_buffer(vfdev, vbuf);

	virtio_fpga_notify(vfdev);
	ret = wait_event_timeout(vfdev->resp_wq,
				 !atomic_read(&port_manager->afu_reset_pending),
				 5 * HZ);

	spin_lock(&port_manager->lock);
	if (port_manager->afu_reset_err) {
		int err = port_manager->afu_reset_err;
		spin_unlock(&port_manager->lock);
		return err;
	}
	spin_unlock(&port_manager->lock);

	return 0;
}




static void virtio_fpga_cmd_fme_bitstream_build_cb(struct virtio_fpga_device *vfdev,
						  struct virtio_fpga_vbuffer *vbuf)
{
	struct virtio_fpga_ctrl_hdr *resp =
		(struct virtio_fpga_ctrl_hdr*)vbuf->resp_buf;
	struct virtio_fpga_fme_manager *fme_manager = vfdev->fme_manager;

	spin_lock(&fme_manager->lock);

	atomic_set(&fme_manager->pr_pending, 0);

	if (resp->type >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
		fme_manager->pr_err = -EINVAL;
		spin_unlock(&fme_manager->lock);
		printk(KERN_ERR "dfl-virtio: pr failed");
		wake_up(&vfdev->resp_wq);
		return;
	}

	wake_up(&vfdev->resp_wq);
	spin_unlock(&fme_manager->lock);
}

int virtio_fpga_cmd_fme_bitstream_build(struct virtio_fpga_device *vfdev,
				       struct dfl_fpga_fme_port_pr *info)
{
	struct virtio_fpga_fme_bitstream_build *cmd_p;
	struct virtio_fpga_vbuffer *vbuf;
	void* resp_buf;
	int ret;

	struct virtio_fpga_fme_manager *fme_manager = vfdev->fme_manager;

	BUG_ON(!fme_manager);

	resp_buf = kzalloc(sizeof(struct virtio_fpga_ctrl_hdr),
			   GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	cmd_p = virtio_fpga_alloc_cmd_resp(vfdev,
					   virtio_fpga_cmd_fme_bitstream_build_cb,
					   &vbuf,
					   sizeof(*cmd_p),
					   sizeof(struct virtio_fpga_ctrl_hdr),
					   resp_buf);
	memset(cmd_p, 0, sizeof(*cmd_p));

	cmd_p->hdr.type = cpu_to_le32(VIRTIO_FPGA_CMD_BITSTREAM_BUILD);
	cmd_p->hdr.port_id = cpu_to_le32(0);
	cmd_p->hdr.is_fme = cpu_to_le32(true);

	cmd_p->port_id = cpu_to_le32(info->port_id);
	cmd_p->length = cpu_to_le64(info->buffer_size);
	cmd_p->flags = cpu_to_le32(info->flags);
	cmd_p->addr = cpu_to_le64(info->buffer_address);

	spin_lock(&fme_manager->lock);
	atomic_set(&fme_manager->pr_pending, 1);
	fme_manager->pr_err = 0;
	spin_unlock(&fme_manager->lock);

	virtio_fpga_queue_ctrl_buffer(vfdev, vbuf);

	virtio_fpga_notify(vfdev);
	ret = wait_event_timeout(vfdev->resp_wq,
				 !atomic_read(&fme_manager->pr_pending),
				 5 * HZ);

	spin_lock(&fme_manager->lock);
	if (fme_manager->pr_err) {
		int err = fme_manager->pr_err;
		spin_unlock(&fme_manager->lock);
		return err;
	}

	spin_unlock(&fme_manager->lock);
	return 0;
}

static void virtio_fpga_cmd_fme_bitstream_mmap_cb(struct virtio_fpga_device *vfdev,
					  struct virtio_fpga_vbuffer *vbuf)
{
	struct virtio_fpga_fme_resp_bitstream_mmap *resp =
		(struct virtio_fpga_fme_resp_bitstream_mmap*)vbuf->resp_buf;
	struct virtio_fpga_fme_manager *fme_manager = vfdev->fme_manager;

	spin_lock(&fme_manager->lock);

	atomic_set(&fme_manager->mmap_pending, 0);

	if (resp->hdr.type >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
		fme_manager->mmap_err = -EINVAL;
		spin_unlock(&fme_manager->lock);
		printk(KERN_ERR "dfl-virtio: map bitstream region failed");
		wake_up(&vfdev->resp_wq);
		return;
	}

	fme_manager->pfn = le64_to_cpu(resp->pfn);

	printk(KERN_DEBUG "dfl-virtio: bitstream map, pfn: 0x%16llx", fme_manager->pfn);

	wake_up(&vfdev->resp_wq);
	spin_unlock(&fme_manager->lock);
}

int virtio_fpga_cmd_fme_bitstream_mmap(struct virtio_fpga_device *vfdev,
				       uint32_t port_id,
				       uint64_t length,
				       uint64_t *pfn) {
	struct virtio_fpga_fme_bitstream_mmap *cmd_p;
	struct virtio_fpga_vbuffer *vbuf;
	void* resp_buf;
	int ret;

	struct virtio_fpga_fme_manager *fme_manager = vfdev->fme_manager;

	BUG_ON(!fme_manager);

	resp_buf = kzalloc(sizeof(struct virtio_fpga_fme_resp_bitstream_mmap),
			   GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	cmd_p = virtio_fpga_alloc_cmd_resp(vfdev,
					   virtio_fpga_cmd_fme_bitstream_mmap_cb,
					   &vbuf,
					   sizeof(*cmd_p),
					   sizeof(struct virtio_fpga_fme_resp_bitstream_mmap),
					   resp_buf);
	memset(cmd_p, 0, sizeof(*cmd_p));

	cmd_p->hdr.type = cpu_to_le32(VIRTIO_FPGA_CMD_BITSTREAM_MMAP);
	cmd_p->hdr.port_id = cpu_to_le32(0);
	cmd_p->hdr.is_fme = cpu_to_le32(true);

	cmd_p->port_id = cpu_to_le32(port_id);
	cmd_p->length = cpu_to_le64(length);

	spin_lock(&fme_manager->lock);
	atomic_set(&fme_manager->mmap_pending, 1);
	fme_manager->mmap_err = 0;
	spin_unlock(&fme_manager->lock);

	virtio_fpga_queue_ctrl_buffer(vfdev, vbuf);

	virtio_fpga_notify(vfdev);
	ret = wait_event_timeout(vfdev->resp_wq,
				 !atomic_read(&fme_manager->mmap_pending),
				 5 * HZ);

	spin_lock(&fme_manager->lock);
	if (fme_manager->mmap_err) {
		int err = fme_manager->mmap_err;
		spin_unlock(&fme_manager->lock);
		return err;
	}

	*pfn = le64_to_cpu(fme_manager->pfn);
	spin_unlock(&fme_manager->lock);

	return 0;
}

static void virtio_fpga_cmd_fme_bitstream_unmap_cb(struct virtio_fpga_device *vfdev,
						 struct virtio_fpga_vbuffer *vbuf)
{
	struct virtio_fpga_ctrl_hdr *resp =
		(struct virtio_fpga_ctrl_hdr*)vbuf->resp_buf;
	struct virtio_fpga_fme_manager *fme_manager = vfdev->fme_manager;

	spin_lock(&fme_manager->lock);

	atomic_set(&fme_manager->munmap_pending, 0);

	if (resp->type >= VIRTIO_FPGA_RESP_ERR_UNSPEC) {
		fme_manager->munmap_err = -EINVAL;
		spin_unlock(&fme_manager->lock);
		printk(KERN_ERR "dfl-virtio: unmap bistream region failed");
		wake_up(&vfdev->resp_wq);
		return;
	}

	wake_up(&vfdev->resp_wq);
	spin_unlock(&fme_manager->lock);
}


int virtio_fpga_cmd_fme_bitstream_unmap(struct virtio_fpga_device *vfdev,
					uint32_t port_id)
{
	struct virtio_fpga_fme_bitstream_unmap *cmd_p;
	struct virtio_fpga_vbuffer *vbuf;
	void* resp_buf;
	int ret;

	struct virtio_fpga_fme_manager *fme_manager = vfdev->fme_manager;

	BUG_ON(!fme_manager);

	resp_buf = kzalloc(sizeof(struct virtio_fpga_ctrl_hdr),
			   GFP_KERNEL);
	if (!resp_buf)
		return -ENOMEM;

	cmd_p = virtio_fpga_alloc_cmd_resp(vfdev,
					   virtio_fpga_cmd_fme_bitstream_unmap_cb,
					   &vbuf,
					   sizeof(*cmd_p),
					   sizeof(struct virtio_fpga_ctrl_hdr),
					   resp_buf);
	memset(cmd_p, 0, sizeof(*cmd_p));

	cmd_p->hdr.type = cpu_to_le32(VIRTIO_FPGA_CMD_BITSTREAM_UNMAP);
	cmd_p->hdr.port_id = cpu_to_le32(0);
	cmd_p->hdr.is_fme = cpu_to_le32(true);

	cmd_p->port_id = cpu_to_le32(port_id);

	spin_lock(&fme_manager->lock);
	atomic_set(&fme_manager->munmap_pending, 1);
	fme_manager->mmap_err = 0;
	spin_unlock(&fme_manager->lock);

	virtio_fpga_queue_ctrl_buffer(vfdev, vbuf);

	virtio_fpga_notify(vfdev);
	ret = wait_event_timeout(vfdev->resp_wq,
				 !atomic_read(&fme_manager->munmap_pending),
				 5 * HZ);

	spin_lock(&fme_manager->lock);
	if (fme_manager->munmap_err) {
		int err = fme_manager->munmap_err;
		spin_unlock(&fme_manager->lock);
		return err;
	}

	spin_unlock(&fme_manager->lock);

	return 0;
}