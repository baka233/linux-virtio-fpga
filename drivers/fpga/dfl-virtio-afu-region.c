// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for FPGA Accelerated Function Unit (AFU) MMIO Region Management
 *
 * Copyright (C) 2017-2018 Intel Corporation, Inc.
 *
 * Authors:
 *   Wu Hao <hao.wu@intel.com>
 *   Xiao Guangrong <guangrong.xiao@linux.intel.com>
 *   Jiahao Zeng <z5661068@gmail.com>
 */
#include "dfl-virtio-afu.h"

/**
 * vafu_mmio_region_init - init function for vafu mmio region support
 * @pdata: vafu platform device's pdata.
 */
void vafu_mmio_region_init(struct dfl_feature_platform_data *pdata)
{
	struct virtio_dfl_afu *vafu = dfl_fpga_pdata_get_private(pdata);

	INIT_LIST_HEAD(&vafu->regions);
}

#define for_each_region(region, vafu)	\
	list_for_each_entry((region), &(vafu)->regions, node)

static struct virtio_dfl_afu_mmio_region *get_region_by_index(struct virtio_dfl_afu *vafu,
						       u32 region_index)
{
	struct virtio_dfl_afu_mmio_region *region;

	for_each_region(region, vafu)
	if (region->index == region_index)
		return region;

	return NULL;
}

/**
 * vafu_mmio_region_add - add a mmio region to given feature dev.
 *
 * @region_index: region index.
 * @region_size: region size.
 * @phys: region's physical address of this region.
 * @flags: region flags (access permission).
 *
 * Return: 0 on success, negative error code otherwise.
 */
int vafu_mmio_region_add(struct dfl_feature_platform_data *pdata,
			u32 region_index, u64 region_size, u64 region_phys, u32 flags)
{
	struct virtio_dfl_afu_mmio_region *region;
	struct virtio_dfl_afu *vafu;
	int ret = 0;

	region = devm_kzalloc(&pdata->dev->dev, sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	region->index = region_index;
	region->size = region_size;
	region->phys = region_phys;
	region->flags = flags;

	mutex_lock(&pdata->lock);

	vafu = dfl_fpga_pdata_get_private(pdata);

	/* check if @index already exists */
	if (get_region_by_index(vafu, region_index)) {
		mutex_unlock(&pdata->lock);
		ret = -EEXIST;
		goto exit;
	}

	region_size = PAGE_ALIGN(region_size);
	region->offset = vafu->region_cur_offset;
	list_add(&region->node, &vafu->regions);

	vafu->region_cur_offset += region_size;
	vafu->num_regions++;
	mutex_unlock(&pdata->lock);

	return 0;

	exit:
	devm_kfree(&pdata->dev->dev, region);
	return ret;
}

/**
 * vafu_mmio_region_destroy - destroy all mmio regions under given feature dev.
 * @pdata: vafu platform device's pdata.
 */
void vafu_mmio_region_destroy(struct dfl_feature_platform_data *pdata)
{
	struct virtio_dfl_afu *vafu = dfl_fpga_pdata_get_private(pdata);
	struct virtio_dfl_afu_mmio_region *tmp, *region;

	list_for_each_entry_safe(region, tmp, &vafu->regions, node) {
		// TODO: call cmd_mmio_unmap to reclaim higher mmio address space from hypervisor
		devm_kfree(&pdata->dev->dev, region);
	}
}

/**
 * vafu_mmio_region_get_by_index - find an vafu region by index.
 * @pdata: vafu platform device's pdata.
 * @region_index: region index.
 * @pregion: ptr to region for result.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int vafu_mmio_region_get_by_index(struct dfl_feature_platform_data *pdata,
				  u32 region_index,
				  struct virtio_dfl_afu_mmio_region *pregion)
{
	struct virtio_dfl_afu_mmio_region *region;
	struct virtio_dfl_afu *vafu;
	int ret = 0;

	mutex_lock(&pdata->lock);
	vafu = dfl_fpga_pdata_get_private(pdata);
	region = get_region_by_index(vafu, region_index);
	if (!region) {
		ret = -EINVAL;
		goto exit;
	}
	*pregion = *region;
	exit:
	mutex_unlock(&pdata->lock);
	return ret;
}

/**
 * vafu_mmio_region_get_by_offset - find an vafu mmio region by offset and size
 *
 * @pdata: vafu platform device's pdata.
 * @offset: region offset from start of the device fd.
 * @size: region size.
 * @pregion: ptr to region for result.
 *
 * Find the region which fully contains the region described by input
 * parameters (offset and size) from the feature dev's region linked list.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int vafu_mmio_region_get_by_offset(struct dfl_feature_platform_data *pdata,
				  u64 offset, u64 size,
				  struct virtio_dfl_afu_mmio_region *pregion)
{
	struct virtio_dfl_afu_mmio_region *region;
	struct virtio_dfl_afu *vafu;
	int ret = 0;

	mutex_lock(&pdata->lock);
	vafu = dfl_fpga_pdata_get_private(pdata);
	for_each_region(region, vafu)
	if (region->offset <= offset &&
	    region->offset + region->size >= offset + size) {
		*pregion = *region;
		goto exit;
	}
	ret = -EINVAL;
exit:
	mutex_unlock(&pdata->lock);
	return ret;
}
