//
// Created by baka233 on 2021/2/4.
//
#include <linux/module.h>

#include "dfl-virtio.h"

#define VIRTIO_ID_FPGA 100

static unsigned int features[]  = {
	VIRTIO_FPGA_F_VFME,
};


static void virtio_fpga_config_changed_work_func(struct work_struct *work)
{
	return;
}

static int virtio_fpga_init(struct virtio_device *vdev)
{
	static vq_callback_t *callbacks[] = {
		virtio_fpga_ctrl_ack
	};

	static const char * const names[] = {
		"control"
	};

	struct virtqueue *vq[1];
	struct virtio_fpga_device *vfdev;
	int ret;

	vfdev = kzalloc(sizeof(struct virtio_fpga_device), GFP_KERNEL);
	if (!vfdev)
		return -ENOMEM;

	vfdev->vdev = vdev;
	vdev->priv = vfdev;
	vfdev->dev = &vdev->dev;

	virtio_cread_le(vfdev->vdev, struct virtio_fpga_config,
			port_num, &vfdev->port_num);

	// initial virito vq, porcess dequeu ctrl
	virtio_fpga_init_vq(&vfdev->ctrlq, virtio_fpga_dequeue_ctrl_func);
	init_waitqueue_head(&vfdev->resp_wq);
	INIT_WORK(&vfdev->config_changed_work,
		  virtio_fpga_config_changed_work_func);

	ret = virtio_find_vqs(vfdev->vdev, 1, vq, callbacks, names, NULL);
	if (ret) {
		dev_err(vfdev->dev, "failed to find virt queue\n");
		goto err_vqs;
	}
	vfdev->ctrlq.vq = vq[0];
	ret = virtio_fpga_alloc_vbufs(vfdev);
	if (ret) {
		dev_err(vfdev->dev, "failed to alloc vbufs\n");
		goto err_vbufs;
	}

	virtio_device_ready(vfdev->vdev);

	dev_dbg(vfdev->dev, "virtio-fpga ready!");

	return 0;
err_vbufs:
	vfdev->vdev->config->del_vqs(vfdev->vdev);
err_vqs:
	kfree(vfdev);
	return ret;

}

static void virtio_fpga_deinit(struct virtio_fpga_device *vfdev)
{
	flush_work(&vfdev->ctrlq.dequeue_work);
	flush_work(&vfdev->config_changed_work);
	vfdev->vdev->config->reset(vfdev->vdev);
	vfdev->vdev->config->del_vqs(vfdev->vdev);
}

static int virtio_enumerate_feature_desc(struct virtio_device *vdev)
{
	struct dfl_fpga_enum_info *info;
	struct dfl_fpga_cdev *cdev;
	struct virtio_fpga_device *vfdev = vdev->priv;
	int ret = 0;

	/* allocate enumeration info via virtio_dev */
	info = dfl_fpga_enum_info_alloc(&vdev->dev);
	if (!info)
		return -ENOMEM;

	/* hack: add virt enum info */
	dfl_fpga_enum_info_add_dfl(info, 0, vfdev->port_num);
	cdev = dfl_fpga_feature_virtio_devs_enumerate(info);
	if (IS_ERR(cdev)) {
		dev_err(cdev->parent, "Enumeration failure\n");
		ret = PTR_ERR(cdev);
		goto enum_info_remove_exit;
	}

	vfdev->cdev = cdev;

enum_info_remove_exit:
	dfl_fpga_enum_info_free(info);
	return ret;
}

static int virtio_fpga_probe(struct virtio_device *vdev)
{
	int ret;

	// init virtio fpga vq and recognize device
	ret = virtio_fpga_init(vdev);
	if (ret)
		goto err_exit;
	ret = virtio_enumerate_feature_desc(vdev);
	if (ret)
		goto virtio_deinit_exit;

	return 0;

virtio_deinit_exit:
	virtio_fpga_deinit(vdev->priv);
err_exit:
	return ret;

}

static void virtio_fpga_remove(struct virtio_device *vdev)
{
	struct virtio_fpga_device *vfdev = vdev->priv;
	dfl_fpga_feature_vdevs_remove(vfdev->cdev);
	virtio_fpga_deinit(vfdev);
}

static void virtio_fpga_config_changed(struct virtio_device *vdev)
{
	struct virtio_fpga_device *vfdev = vdev->priv;

	schedule_work(&vfdev->config_changed_work);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_FPGA, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_fpga_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtio_fpga_probe,
	.remove = virtio_fpga_remove,
	.config_changed = virtio_fpga_config_changed
};

module_virtio_driver(virtio_fpga_driver);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio FPGA driver");
MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("baka233 <z5661068@gmail.com>");

