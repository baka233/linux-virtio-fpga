//
// Created by baka233 on 2021/2/4.
//

#include <linux/module.h>
#include "dfl.h"
#include "dfl-virtio.h"

static int vfme_open(struct inode *inode, struct file *filp)
{
	struct platform_device *fdev = dfl_fpga_inode_to_feature_dev(inode);
	struct dfl_feature_platform_data *pdata = dev_get_platdata(&fdev->dev);
	int ret;

	if (WARN_ON(!pdata))
		return -ENODEV;

	mutex_lock(&pdata->lock);
	ret = dfl_feature_dev_use_begin(pdata, filp->f_flags & O_EXCL);
	if (!ret) {
		dev_dbg(&fdev->dev, "Device File Opened %d Times\n",
			dfl_feature_dev_use_count(pdata));
		filp->private_data = pdata;
	}
	mutex_unlock(&pdata->lock);

	return ret;
}

static int vfme_release(struct inode *inode, struct file *filp)
{
	struct dfl_feature_platform_data *pdata = filp->private_data;
	struct platform_device *pdev = pdata->dev;

	dev_dbg(&pdev->dev, "Device File Release\n");

	mutex_lock(&pdata->lock);
	dfl_feature_dev_use_end(pdata);

	mutex_unlock(&pdata->lock);

	return 0;
}

static long vfme_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct dfl_feature_platform_data *pdata = filp->private_data;
	struct platform_device *pdev = pdata->dev;

	dev_dbg(&pdev->dev, "%s cmd 0x%x\n", __func__, cmd);

	switch (cmd) {
	case DFL_FPGA_GET_API_VERSION:
		return DFL_FPGA_API_VERSION;
	case DFL_FPGA_CHECK_EXTENSION:
		// no extension for now
		return 0;
	case DFL_FPGA_FME_PORT_PR:
		/* need to implement */
		/* ----------------- */
	default:
		/* not implement now */
		break;
	}

	return -EINVAL;
}

static const struct file_operations vfme_fops = {
	.owner		= THIS_MODULE,
	.open		= vfme_open,
	.release	= vfme_release,
	.unlocked_ioctl = vfme_ioctl,
};

static int vfme_probe(struct platform_device *pdev)
{
	int ret;

	ret = dfl_fpga_dev_ops_register(pdev, &vfme_fops, THIS_MODULE);
	if (ret)
		goto ret_exit;

ret_exit:
	return ret;
}

static int vfme_remove(struct platform_device *pdev)
{
	dfl_fpga_dev_ops_unregister(pdev);
	return 0;
}

static struct platform_driver vfme_driver = {
	.driver	= {
		.name       = DFL_FPGA_FEATURE_DEV_VFME,
	},
	.probe   = vfme_probe,
	.remove  = vfme_remove,
};

module_platform_driver(vfme_driver);

MODULE_DESCRIPTION("FPGA Management Virtio Engine driver");
MODULE_AUTHOR("baka233<z5661068@gmail.com>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:dfl-vfme");
