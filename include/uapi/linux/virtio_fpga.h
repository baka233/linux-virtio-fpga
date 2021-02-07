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

	/* error command */
	VIRTIO_FPGA_RESP_ERR_UNSPEC = 0x1100,
};

struct virtio_fpga_ctrl_hdr {
	__le32 type;
	__le32 flags;
	__le32 padding;
};

struct virtio_fpga_config {
	__le32 port_num;
};

#define VIRTIO_FPGA_F_VFME 0

#endif //__VIRTIO_FPGA_H
