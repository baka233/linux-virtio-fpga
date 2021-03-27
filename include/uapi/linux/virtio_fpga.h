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
	VIRTIO_FPGA_CMD_MMIO_UNMAP,
	VIRTIO_FPGA_CMD_BITSTREAM_MMAP,
	VIRTIO_FPGA_CMD_BITSTREAM_UNMAP,
	VIRTIO_FPGA_CMD_BITSTREAM_BUILD,
	VIRTIO_FPGA_CMD_AFU_RESET,

	/* ok command */
	VIRTIO_FPGA_RESP_OK_NODATA = 0x1000,
	VIRTIO_FPGA_RESP_OK_PORT_INFO,
	VIRTIO_FPGA_RESP_OK_REGION_INFO,
	VIRTIO_FPGA_RESP_OK_DMA_REGION,
	VIRTIO_FPGA_RESP_OK_MMIO_MAP,
	VIRTIO_FPGA_RESP_OK_BITSTREAM_MMAP,

	/* error command */
	VIRTIO_FPGA_RESP_ERR_UNSPEC = 0x1100,
	VIRTIO_FPGA_RESP_ERR_PORT_NOT_EXIST,
	VIRTIO_FPGA_RESP_ERR_IOVA_NOT_EXIST,
	VIRTIO_FPGA_RESP_ERR_REGION_NOT_EXIST,
};

struct virtio_fpga_ctrl_hdr {
	__le32 type;
	__le32 flags;
	__le32 port_id;
	__le32 is_fme;
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

struct virtio_fpga_afu_mmio_map {
	struct virtio_fpga_ctrl_hdr hdr;
	__le64 offset;
	__le64 size;
	__le32 flags;
	__le32 padding;
};

struct virtio_fpga_afu_resp_mmio_map {
	struct virtio_fpga_ctrl_hdr hdr;
	__le64 pfn;
};

struct virtio_fpga_afu_mmio_unmap {
	struct virtio_fpga_ctrl_hdr hdr;
	__le64 offset;
};

struct virtio_fpga_config {
	__le32 port_num;
	__le32 has_fme;
};

struct virtio_fpga_fme_bitstream_mmap {
	struct virtio_fpga_ctrl_hdr hdr;
	__le64 length;
	__le32 port_id;
	__le32 padding;
};

struct virtio_fpga_fme_resp_bitstream_mmap {
	struct virtio_fpga_ctrl_hdr hdr;
	__le64 pfn;
};

struct virtio_fpga_fme_bitstream_unmap {
	struct virtio_fpga_ctrl_hdr hdr;
	__le32 port_id;
	__le32 padding;
};

struct virtio_fpga_fme_bitstream_build {
	struct virtio_fpga_ctrl_hdr hdr;
	__le32 flags;
	__le32 port_id;
	__le64 addr;
	__le64 length;
};

#define VIRTIO_FPGA_F_VFME 0

#endif //__VIRTIO_FPGA_H
