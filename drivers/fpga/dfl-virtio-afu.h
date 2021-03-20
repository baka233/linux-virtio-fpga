//
// Created by baka233 on 2021/3/14.
//

#ifndef __VIRTIO_AFU_H
#define __VIRTIO_AFU_H

#include "dfl-virtio.h"

/**
 * struct virtio_dfl_afu_mmio_region - vafu mmio region data structure
 *
 * @index: region index.
 * @flags: region flags (access permission).
 * @size: region size.
 * @offset: region offset from start of the device fd.
 * @phys: region's physical address.
 * @node: node to add to afu feature dev's region list.
 */
struct virtio_dfl_afu_mmio_region {
	u32 index;
	u32 flags;
	u64 size;
	u64 offset;
	u64 phys;
	struct list_head node;
};

/**
 * struct virtio_fpga_afu_dma_region - vafu DMA region data structure
 *
 * @user_addr: region userspace virtual address.
 * @length: region length.
 * @iova: region IO virtual address.
 * @node: rb tree node.
 */
struct virtio_dfl_afu_dma_region {
	u64 user_addr;
	u64 length;
	u64 iova;
	struct rb_node node;
};

/**
 * struct virtio_dfl_afu - vafu device data structure
 *
 * @region_cur_offset: current region offset from start to the device fd.
 * @num_regions: num of mmio regions.
 * @regions: the mmio region linked list of this afu feature device.
 * @num_umsgs: num of umsgs.
 * @flags: flag of vafu
 * @pdata: afu platform device's pdata.
 */
struct virtio_dfl_afu {
	u64 region_cur_offset;
	int num_regions;
	u8 num_umsgs;
	int flags;
	struct list_head regions;
	struct rb_root dma_regions;

	struct dfl_feature_platform_data *pdata;
};


// dma region
void vafu_dma_region_init(struct dfl_feature_platform_data *pdata);

void vafu_dma_region_destroy(struct dfl_feature_platform_data *pdata);

int vafu_dma_region_map(struct dfl_feature_platform_data *pdata, struct dfl_fpga_port_dma_map *map);

int vafu_dma_region_unmap(struct dfl_feature_platform_data *pdata, u64 iova);

// mmio region

void vafu_mmio_region_init(struct dfl_feature_platform_data *pdata);

int vafu_mmio_region_add(struct dfl_feature_platform_data *pdata,
			 u32 region_index, u64 region_size, u64 phys, u32 flags);

void vafu_mmio_region_destroy(struct dfl_feature_platform_data *pdata);

int vafu_mmio_region_get_by_index(struct dfl_feature_platform_data *pdata,
				  u32 region_index,
				  struct virtio_dfl_afu_mmio_region *pregion);

int vafu_mmio_region_get_by_offset(struct dfl_feature_platform_data *pdata,
				   u64 offset, u64 size,
				   struct virtio_dfl_afu_mmio_region *pregion);

#endif //__DFL_VIRTIO_AFU_H
