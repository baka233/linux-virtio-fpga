//
// Created by baka233 on 2021/2/4.
//

#define DEBUG
#include <linux/module.h>
#include "dfl-virtio-afu.h"
#include "dfl.h"

static long
vafu_ioctl_get_info(struct dfl_feature_platform_data *pdata, void __user *arg)
{
	struct dfl_fpga_port_info info;
	struct virtio_dfl_afu *vafu;
	unsigned long minsz;
	int ret;

	minsz = offsetofend(struct dfl_fpga_port_info, num_umsgs);

	if (copy_from_user(&info, arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz)
		return -EINVAL;

	vafu = dfl_fpga_pdata_get_private(pdata);

	info.flags = vafu->flags;
	info.num_regions = vafu->num_regions;
	info.num_umsgs = vafu->num_umsgs;
	info.flags = vafu->flags;

	dev_dbg(&pdata->dev->dev, "%s: flags: 0x%x, num_regions: %d, num_umsgs: %d",
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
	struct virtio_dfl_afu *vafu;
	struct virtio_dfl_afu_mmio_region region;
	unsigned long minsz;
	long ret;

	minsz = offsetofend(struct dfl_fpga_port_region_info, offset);

	if (copy_from_user(&rinfo, arg, minsz))
		return -EFAULT;

	if (rinfo.argsz < minsz || rinfo.padding)
		return -EINVAL;

	vafu = dfl_fpga_pdata_get_private(pdata);
	ret = vafu_mmio_region_get_by_index(pdata, rinfo.index, &region);
	if (ret)
		return ret;

	rinfo.flags = region.flags;
	rinfo.size = region.size;
	rinfo.offset = region.offset;

	if (copy_to_user(arg, &rinfo, sizeof(rinfo)))
		return -EFAULT;

	return 0;
}

static long
vafu_ioctl_dma_map(struct dfl_feature_platform_data *pdata,
			       void __user* args)
{
	struct dfl_fpga_port_dma_map map;
	unsigned long minsz;
	long ret;

	minsz = offsetofend(struct dfl_fpga_port_dma_map, iova);

	if (copy_from_user(&map, args, minsz))
		return -EFAULT;

	if (map.argsz < minsz || map.flags)
		return -EINVAL;

	ret = vafu_dma_region_map(pdata, &map);
	if (ret)
		return ret;

	if (copy_to_user(args, &map, sizeof(map))) {
		vafu_dma_region_unmap(pdata, map.iova);
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
	unsigned long minsz;

	minsz = offsetofend(struct dfl_fpga_port_dma_unmap, iova);

	if (copy_from_user(&unmap, args, minsz))
		return -EFAULT;

	if (unmap.argsz < minsz || unmap.flags)
		return -EINVAL;

	return vafu_dma_region_unmap(pdata, unmap.iova);
}

static long
vafu_ioctl_port_reset(struct dfl_feature_platform_data *pdata)
{
	struct virtio_fpga_device *vfdev;
	__u32 port_id;

	port_id = pdata_get_port_id(pdata);
	vfdev = pdata_get_vfdev(pdata);

	return virtio_fpga_cmd_afu_reset(vfdev, port_id);
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
	vafu_dma_region_init(pdata);
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
	vafu_dma_region_destroy(pdata);
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
	case DFL_FPGA_PORT_RESET:
		return vafu_ioctl_port_reset(pdata);
	default:
		break;
	}

	return -EINVAL;
}


static int afu_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct platform_device *pdev = filp->private_data;
	struct dfl_feature_platform_data *pdata;
	u64 size = vma->vm_end - vma->vm_start;
	struct virtio_dfl_afu_mmio_region region;
	u64 offset;
	int ret;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	pdata = dev_get_platdata(&pdev->dev);

	offset = vma->vm_pgoff << PAGE_SHIFT;
	ret = vafu_mmio_region_get_by_offset(pdata, offset, size, &region);
	if (ret)
		return ret;

	if (!(region.flags & DFL_PORT_REGION_MMAP))
		return -EINVAL;


	if ((vma->vm_flags & VM_READ) && !(region.flags & DFL_PORT_REGION_READ))
		return -EPERM;

	if ((vma->vm_flags & VM_WRITE) &&
	    !(region.flags & DFL_PORT_REGION_WRITE))
		return -EPERM;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	dev_dbg(&pdev->dev, "regions.phys is 0x%0llx", region.phys);

	return remap_pfn_range(vma, vma->vm_start,
			       (region.phys + (offset - region.offset)) >> PAGE_SHIFT,
			       size, vma->vm_page_prot);
}

static const struct file_operations afu_fops = {
	.owner = THIS_MODULE,
	.open = afu_open,
	.release = afu_release,
	.unlocked_ioctl = afu_ioctl,
	.mmap = afu_mmap,
};


static void vafu_dev_destroy(struct platform_device *pdev)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(&pdev->dev);

	vafu_mmio_region_destroy(pdata);
}

static int vafu_dev_init(struct platform_device *pdev)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(&pdev->dev);
	struct virtio_fpga_device *vfdev;
	struct virtio_dfl_afu *vafu;
	int ret;
	int port_id;

	dev_dbg(&pdev->dev, "try to initial regions");
	vfdev = pdata_get_vfdev(pdata);
	port_id = pdata_get_port_id(pdata);
	vafu = devm_kzalloc(&pdev->dev, sizeof(*vafu), GFP_KERNEL);
	if (!vafu)
		return -ENOMEM;

	vafu->pdata = pdata;

	dfl_fpga_pdata_set_private(pdata, vafu);
	vafu_mmio_region_init(pdata);

	struct dfl_fpga_port_info info;
	ret = virtio_fpga_cmd_get_port_info(vfdev, port_id, &info);
	if (ret)
		goto mutex_release;

	vafu->num_umsgs = info.num_umsgs;
	vafu->flags = info.flags;

	int i;
	// TODO: add unmap recollect resource
	for (i = 0; i < info.num_regions; i++) {
		uint64_t pfn;
		struct dfl_fpga_port_region_info rinfo;
		rinfo.index = i;
		rinfo.argsz = sizeof(rinfo);
		ret = virtio_fpga_cmd_get_port_region_info(vfdev, port_id, &rinfo);
		if (ret)
			goto destroy_regions;

		dev_info(&pdev->dev, "%s, region_info: index: %d, offset: %lld, size: %lld, flags: %x", __func__, rinfo.index, rinfo.offset, rinfo.size, rinfo.flags);

		if (rinfo.flags & DFL_PORT_REGION_MMAP) {
			ret = virtio_fpga_cmd_mmio_map(vfdev, port_id,
						       rinfo.offset, rinfo.size,
						       rinfo.flags, &pfn);
			if (ret)
				goto destroy_regions;
		}

		dev_info(&pdev->dev, "%s, region_map pfn: 0x%0llx", __func__, pfn);

		ret = vafu_mmio_region_add(pdata, i, rinfo.size, pfn << PAGE_SHIFT, rinfo.flags);
		if (ret)
			goto destroy_regions;
	}

	ret = virtio_fpga_cmd_afu_reset(vfdev, port_id);
	if (ret < 0) {
		dev_warn(&pdev->dev, "reset vafu failed");
	}

	dev_info(&pdev->dev, "init vafu successfully");

	return 0;

destroy_regions:
	dev_err(&pdev->dev, "init vafu failed, err: %d", ret);
	vafu_mmio_region_destroy(pdata);
mutex_release:
	return ret;
}

static int afu_probe(struct platform_device *pdev)
{
	int ret;

	ret = vafu_dev_init(pdev);
	if (ret)
		goto exit;

	ret = dfl_fpga_dev_ops_register(pdev, &afu_fops, THIS_MODULE);
	if (ret) {
		dev_dbg(&pdev->dev, "probe afu failed");
		dfl_fpga_dev_feature_uinit(pdev);
		goto dev_destroy;
	}

	return 0;
dev_destroy:
	vafu_dev_destroy(pdev);
exit:
	return ret;
}

static int afu_remove(struct platform_device *pdev)
{
	dev_dbg(&pdev->dev, "%s\n", __func__);

	dfl_fpga_dev_ops_unregister(pdev);
	vafu_dev_destroy(pdev);

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
