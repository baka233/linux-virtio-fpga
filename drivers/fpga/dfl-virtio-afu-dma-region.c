//
// Created by baka233 on 2021/3/14.
//

#include "dfl-virtio-afu.h"

void vafu_dma_region_init(struct dfl_feature_platform_data *pdata)
{
	struct virtio_dfl_afu *vafu = dfl_fpga_pdata_get_private(pdata);

	vafu->dma_regions = RB_ROOT;
}

/**
 * dma_region_check_iova - check if memory area is fully contained in the region
 * @region: dma memory region
 * @iova: address of the dma memory area
 * @size: size of the dma memory area
 *
 * Compare the dma memory area defined by @iova and @size with given dma region.
 * Return true if memory area is fully contained in the region, otherwise false.
 */
static bool dma_region_check_iova(struct virtio_dfl_afu_dma_region *region,
				  u64 iova, u64 size)
{
	if (!size && region->iova != iova)
		return false;

	return (region->iova <= iova) &&
	       (region->length + region->iova >= iova + size);
}

/**
 * vafu_dma_region_add - add given dma region to rbtree
 * @pdata: feature device platform data
 * @region: dma region to be added
 *
 * Return 0 for success, -EEXIST if dma region has already been added.
 *
 * Needs to be called with pdata->lock heold.
 */
static int vafu_dma_region_add(struct dfl_feature_platform_data *pdata,
			      struct virtio_dfl_afu_dma_region *region)
{
	struct virtio_dfl_afu *vafu = dfl_fpga_pdata_get_private(pdata);
	struct rb_node **new, *parent = NULL;

	dev_dbg(&pdata->dev->dev, "add region (iova = %llx)\n",
		(unsigned long long)region->iova);

	new = &vafu->dma_regions.rb_node;

	while (*new) {
		struct virtio_dfl_afu_dma_region *this;

		this = container_of(*new, struct virtio_dfl_afu_dma_region, node);

		parent = *new;

		if (dma_region_check_iova(this, region->iova, region->length))
			return -EEXIST;

		if (region->iova < this->iova)
			new = &((*new)->rb_left);
		else if (region->iova > this->iova)
			new = &((*new)->rb_right);
		else
			return -EEXIST;
	}

	rb_link_node(&region->node, parent, new);
	rb_insert_color(&region->node, &vafu->dma_regions);

	return 0;
}

/**
 * afu_dma_region_remove - remove given dma region from rbtree
 * @pdata: feature device platform data
 * @region: dma region to be removed
 *
 * Needs to be called with pdata->lock heold.
 */
static void vafu_dma_region_remove(struct dfl_feature_platform_data *pdata,
				  struct virtio_dfl_afu_dma_region *region)
{
	struct virtio_dfl_afu *vafu;

	dev_dbg(&pdata->dev->dev, "del region (iova = %llx)\n",
		(unsigned long long)region->iova);

	vafu = dfl_fpga_pdata_get_private(pdata);
	rb_erase(&region->node, &vafu->dma_regions);
}

/**
 * vafu_dma_region_destroy - destroy all regions in rbtree
 * @pdata: feature device platform data
 *
 * Needs to be called with pdata->lock heold.
 */
void vafu_dma_region_destroy(struct dfl_feature_platform_data *pdata)
{
	struct virtio_dfl_afu *vafu = dfl_fpga_pdata_get_private(pdata);
	struct rb_node *node = rb_first(&vafu->dma_regions);
	struct virtio_dfl_afu_dma_region *region;
	struct virtio_fpga_device *vfdev;
	__u32 port_id;

	port_id = pdata_get_port_id(pdata);
	vfdev = pdata_get_vfdev(pdata);

	while (node) {
		region = container_of(node, struct virtio_dfl_afu_dma_region, node);

		dev_dbg(&pdata->dev->dev, "del region (iova = %llx)\n",
			(unsigned long long)region->iova);

		rb_erase(node, &vafu->dma_regions);

		// unmap dma resource
		virtio_fpga_cmd_dma_unmap(vfdev, port_id, region->iova);

		node = rb_next(node);
		kfree(region);
	}
}

/**
 * vafu_dma_region_find - find the dma region from rbtree based on iova and size
 * @pdata: feature device platform data
 * @iova: address of the dma memory area
 * @size: size of the dma memory area
 *
 * It finds the dma region from the rbtree based on @iova and @size:
 * - if @size == 0, it finds the dma region which starts from @iova
 * - otherwise, it finds the dma region which fully contains
 *   [@iova, @iova+size)
 * If nothing is matched returns NULL.
 *
 * Needs to be called with pdata->lock held.
 */
struct virtio_dfl_afu_dma_region *
vafu_dma_region_find(struct dfl_feature_platform_data *pdata, u64 iova, u64 size)
{
	struct virtio_dfl_afu *vafu = dfl_fpga_pdata_get_private(pdata);
	struct rb_node *node = vafu->dma_regions.rb_node;
	struct device *dev = &pdata->dev->dev;

	while (node) {
		struct virtio_dfl_afu_dma_region *region;

		region = container_of(node, struct virtio_dfl_afu_dma_region, node);

		if (dma_region_check_iova(region, iova, size)) {
			dev_dbg(dev, "find region (iova = %llx)\n",
				(unsigned long long)region->iova);
			return region;
		}

		if (iova < region->iova)
			node = node->rb_left;
		else if (iova > region->iova)
			node = node->rb_right;
		else
			/* the iova region is not fully covered. */
			break;
	}

	dev_dbg(dev, "region with iova %llx and size %llx is not found\n",
		(unsigned long long)iova, (unsigned long long)size);

	return NULL;
}

/**
 * vafu_dma_region_find_iova - find the dma region from rbtree by iova
 * @pdata: feature device platform data
 * @iova: address of the dma region
 *
 * Needs to be called with pdata->lock held.
 */
static struct virtio_dfl_afu_dma_region *
vafu_dma_region_find_iova(struct dfl_feature_platform_data *pdata, u64 iova)
{
	return vafu_dma_region_find(pdata, iova, 0);
}

int vafu_dma_region_map(struct dfl_feature_platform_data *pdata, struct dfl_fpga_port_dma_map *map)
{
	struct virtio_fpga_device *vfdev;
	struct virtio_dfl_afu_dma_region *dma_region;
	__u32 port_id;
	int ret;

	port_id = pdata_get_port_id(pdata);
	vfdev = pdata_get_vfdev(pdata);

	dma_region = kzalloc(sizeof(*dma_region), GFP_KERNEL);
	if (!dma_region)
		return -ENOMEM;

	ret = virtio_fpga_cmd_dma_map(vfdev, port_id, map->flags, map->user_addr, map->length, &map->iova);
	if (ret)
		return ret;

	dma_region->iova = map->iova;
	dma_region->user_addr = map->user_addr;
	dma_region->length = map->length;
	ret = vafu_dma_region_add(pdata, dma_region);
	if (ret) {
		virtio_fpga_cmd_dma_unmap(vfdev, port_id, map->iova);
		return ret;
	}

	return 0;
}

int vafu_dma_region_unmap(struct dfl_feature_platform_data *pdata, u64 iova)
{
	struct virtio_fpga_device* vfdev;
	struct virtio_dfl_afu_dma_region* region;
	uint64_t port_id;
	int ret;

	vfdev = pdata_get_vfdev(pdata);
	port_id = pdata_get_port_id(pdata);

	mutex_lock(&pdata->lock);
	region = vafu_dma_region_find_iova(pdata, iova);
	if (!region) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	vafu_dma_region_remove(pdata, region);
	kfree(region);
	ret = virtio_fpga_cmd_dma_unmap(vfdev, port_id, iova);
	if (ret)
		goto exit_unlock;
	mutex_unlock(&pdata->lock);
	return 0;
exit_unlock:
	mutex_unlock(&pdata->lock);
	return ret;
}
