//
// Created by baka233 on 2021/2/6.
//

#ifndef __VIRTIO_FPGA_H
#define __VIRTIO_FPGA_H

enum virtio_fpga_ctrl_type {
	VIRTIO_FPGA_UNDEFINED = 0,

	/* fme command */
	VIRTIO_FPGA_CMD_FME_PORT_PR = 0x0100,

	/* afu command */
	VIRTIO_FPGA_CMD_GET_PORT_INFO = 0x0200,
	VIRTIO_FPGA_CMD_GET_PORT_REGION_INFO,
	VIRTIO_FPGA_CMD_DMA_MAP,
	VIRTIO_FPGA_CMD_DMA_UNMAP,
	VIRTIO_FPGA_CMD_MMIO_MAP,

	/* ok command */
	VIRTIO_FPGA_RESP_OK_NODATA = 0x1000,
	VIRTIO_FPGA_RESP_OK_PORT_INFO,
	VIRTIO_FPGA_RESP_OK_REGION_INFO,
	VIRTIO_FPGA_RESP_OK_DMA_REGION,
	VIRTIO_FPGA_RESP_OK_MMIO_MAP,

	/* error command */
	VIRTIO_FPGA_RESP_ERR_UNSPEC = 0x1100,
	VIRTIO_FPGA_RESP_ERR_PORT_NOT_EXIST,
	VIRTIO_FPGA_RESP_ERR_IOVA_NOT_EXIST,
};

struct virtio_fpga_ctrl_hdr {
	__le32 type;
	__le32 flags;
	__le32 port_id;
	__le32 is_fme;
	__le32 padding;
};

struct virtio_fpga_afu_port_info {
	struct virtio_fpga_ctrl_hdr hdr;
};

struct virtio_fpga_afu_resp_port_info {
	struct virtio_fpga_ctrl_hdr hdr;
	__le32 flags;
	__le32 num_regions;
	__le32 num_umsgs;
};

struct virtio_fpga_afu_region_info {
	struct virtio_fpga_ctrl_hdr hdr;
	__le32 index;
	__le32 padding;

};

struct virtio_fpga_afu_resp_region_info {
	struct virtio_fpga_ctrl_hdr hdr;
	__le32 flags;
	__le32 padding;
	__le64 size;
	__le64 offset;
};

struct virtio_fpga_afu_dma_map {
	struct virtio_fpga_ctrl_hdr hdr;
	__le32 flags;
	__le64 length;
};

struct virtio_fpga_afu_resp_dma_map {
	struct virtio_fpga_ctrl_hdr hdr;
	__le64 iova;
	__le64 pfn;
	__le64 num_page;
};

struct virtio_fpga_afu_dma_unmap {
	struct virtio_fpga_ctrl_hdr hdr;
	__le64 iova;
};

struct virtio_fpga_afu_resp_dma_unmap {
	struct virtio_fpga_ctrl_hdr hdr;
};

struct virtio_fpga_config {
	__le32 port_num;
};

#define VIRTIO_FPGA_F_VFME 0

#endif //__VIRTIO_FPGA_H
