//
// Created by baka233 on 2021/2/4.
//

#include <linux/module.h>
#include "dfl-virtio.h"
#include "dfl.h"

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

	return ret;
}

static int afu_release(struct inode *inode, struct file *filp)
{
	struct platform_device *pdev = filp->private_data;
	struct dfl_feature_platform_data *pdata;

	dev_dbg(&pdev->dev, "Device File Release\n");

	pdata = dev_get_platdata(&pdev->dev);

	mutex_lock(&pdata->lock);
	dfl_feature_dev_use_end(pdata);
	/* TODO: need send port_reset command to host */
	mutex_unlock(&pdata->lock);

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
	case DFL_FPGA_CHECK_EXTENSION:
	case DFL_FPGA_PORT_GET_INFO:
	case DFL_FPGA_PORT_GET_REGION_INFO:
	case DFL_FPGA_PORT_DMA_MAP:
	case DFL_FPGA_PORT_DMA_UNMAP:
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

	dev_dbg(&pdev->dev, "%s\n", __func__);
	ret = dfl_fpga_dev_ops_register(pdev, &afu_fops, THIS_MODULE);

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
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:dfl-port");
