//
// Created by baka233 on 2021/2/4.
//

#define DEBUG
#include <linux/module.h>
#include "dfl-virtio.h"
#include "dfl.h"

static long
vafu_ioctl_get_info(struct dfl_feature_platform_data *pdata, void __user *arg)
{
	struct dfl_fpga_port_info info;
	struct virtio_fpga_device *vfdev;
	unsigned long minsz;
	int ret;
	uint32_t port_id;

	minsz = offsetofend(struct dfl_fpga_port_info, num_umsgs);

	if (copy_from_user(&info, arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz)
		return -EINVAL;

	vfdev = pdata_get_vfdev(pdata);
	port_id = pdata_get_port_id(pdata);

	ret = virtio_fpga_cmd_get_port_info(vfdev, port_id, &info);
	dev_dbg(vfdev->dev, "%s: flags: 0x%x, num_regions: %d, num_umsgs: %d",
		__func__,
		info.flags,
		info.num_regions,
		info.num_umsgs);
	if (ret)
		return ret;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static long
vafu_ioctl_get_region_info(struct dfl_feature_platform_data *pdata,
				      void __user *arg)
{
	struct dfl_fpga_port_region_info rinfo;
	struct virtio_fpga_device *vfdev;
	unsigned long minsz;
	long ret;
	uint32_t port_id;

	minsz = offsetofend(struct dfl_fpga_port_region_info, offset);

	if (copy_from_user(&rinfo, arg, minsz))
		return -EFAULT;

	if (rinfo.argsz < minsz || rinfo.padding)
		return -EINVAL;

	port_id = pdata_get_port_id(pdata);
	vfdev = pdata_get_vfdev(pdata);
	ret = virtio_fpga_cmd_get_port_region_info(vfdev, port_id, &rinfo);
	if (ret)
		return ret;

	if (copy_to_user(arg, &rinfo, sizeof(rinfo)))
		return -EFAULT;

	return 0;
}

static long
vafu_ioctl_dma_map(struct dfl_feature_platform_data *pdata,
			       void __user* args)
{
	struct dfl_fpga_port_dma_map map;
	struct virtio_fpga_device *vfdev;
	unsigned long minsz;
	long ret;
	__u32 port_id;

	minsz = offsetofend(struct dfl_fpga_port_dma_map, iova);

	if (copy_from_user(&map, args, minsz))
		return -EFAULT;

	if (map.argsz < minsz || map.flags)
		return -EINVAL;


	port_id = pdata_get_port_id(pdata);
	vfdev = pdata_get_vfdev(pdata);
	ret = virtio_fpga_cmd_dma_map(vfdev, port_id, map.flags, map.user_addr, map.length, &map.iova);
	if (ret)
		return ret;

	if (copy_to_user(args, &map, sizeof(map))) {
		virtio_fpga_cmd_dma_unmap(vfdev, port_id, map.iova);
		return -EFAULT;
	}

	dev_dbg(&pdata->dev->dev, "dma map: ua=%llx, len=%llx, iova=%llx\n",
		(unsigned long long)map.user_addr,
		(unsigned long long)map.length,
		(unsigned long long)map.iova);

	return 0;
}

static long
vafu_ioctl_dma_unmap(struct dfl_feature_platform_data *pdata,
			       void __user* args)
{
	struct dfl_fpga_port_dma_unmap unmap;
	struct virtio_fpga_device* vfdev;
	unsigned long minsz;
	uint64_t port_id;

	minsz = offsetofend(struct dfl_fpga_port_dma_unmap, iova);

	if (copy_from_user(&unmap, args, minsz))
		return -EFAULT;

	if (unmap.argsz < minsz || unmap.flags)
		return -EINVAL;

	vfdev = pdata_get_vfdev(pdata);
	port_id = pdata_get_port_id(pdata);

	return virtio_fpga_cmd_dma_unmap(vfdev, port_id, unmap.iova);
}

static int afu_open(struct inode *inode, struct file *filp)
{
	struct platform_device *fdev = dfl_fpga_inode_to_feature_dev(inode);
	struct dfl_feature_platform_data *pdata;
	int ret;

	pdata = dev_get_platdata(&fdev->dev);
	if (WARN_ON(!pdata))
		return -ENODEV;

	mutex_lock(&pdata->lock);
	ret = dfl_feature_dev_use_begin(pdata, filp->f_flags & O_EXCL);
	if (!ret) {
		dev_dbg(&fdev->dev, "Device File Opened %d Times\n",
			dfl_feature_dev_use_count(pdata));
		filp->private_data = fdev;
	}
	mutex_unlock(&pdata->lock);
	dev_dbg(&fdev->dev, "file open");

	return ret;
}

static int afu_release(struct inode *inode, struct file *filp)
{
	struct platform_device *pdev = filp->private_data;
	struct dfl_feature_platform_data *pdata;

	pdata = dev_get_platdata(&pdev->dev);

	mutex_lock(&pdata->lock);
	dfl_feature_dev_use_end(pdata);
	/* TODO: need send port_reset command to host */
	mutex_unlock(&pdata->lock);
	dev_dbg(&pdev->dev, "Device File Release\n");

	return 0;
}

static long afu_ioctl(struct file *filp, unsigned int cmd, unsigned long args)
{
	struct platform_device *pdev = filp->private_data;
	struct dfl_feature_platform_data *pdata;

	dev_dbg(&pdev->dev, "%s cmd 0x%x\n", __func__, cmd);

	pdata = dev_get_platdata(&pdev->dev);

	switch (cmd) {
	case DFL_FPGA_GET_API_VERSION:
		return DFL_FPGA_API_VERSION;
	case DFL_FPGA_CHECK_EXTENSION:
		// no extension for now
		return 0;
	case DFL_FPGA_PORT_GET_INFO:
		return vafu_ioctl_get_info(pdata, (void __user*)args);
	case DFL_FPGA_PORT_GET_REGION_INFO:
		return vafu_ioctl_get_region_info(pdata, (void __user*)args);
	case DFL_FPGA_PORT_DMA_MAP:
		return vafu_ioctl_dma_map(pdata, (void __user*)args);
	case DFL_FPGA_PORT_DMA_UNMAP:
		return vafu_ioctl_dma_unmap(pdata, (void __user*)args);
	default:
		break;
	}

	return -EINVAL;
}

static const struct file_operations afu_fops = {
	.owner = THIS_MODULE,
	.open = afu_open,
	.release = afu_release,
	.unlocked_ioctl = afu_ioctl,
	// .mmap = afu_mmap,
};

static int afu_probe(struct platform_device *pdev)
{
	int ret;

	ret = dfl_fpga_dev_ops_register(pdev, &afu_fops, THIS_MODULE);
	if (ret) {
		dev_dbg(&pdev->dev, "probe afu failed");
		dfl_fpga_dev_feature_uinit(pdev);
	} else {
		dev_dbg(&pdev->dev, "probe afu successfully!");
	}

	return ret;
}

static int afu_remove(struct platform_device *pdev)
{
	dev_dbg(&pdev->dev, "%s\n", __func__);

	dfl_fpga_dev_ops_unregister(pdev);

	return 0;
}

static struct platform_driver vafu_driver = {
	.driver	= {
		.name	    = DFL_FPGA_FEATURE_DEV_VPORT,
	},
	.probe   = afu_probe,
	.remove  = afu_remove,
};

module_platform_driver(vafu_driver);

MODULE_DESCRIPTION("FPGA Accelerated Function Unit Virtio driver");
MODULE_AUTHOR("baka233(z5661068@gmail.com");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:dfl-vport");
