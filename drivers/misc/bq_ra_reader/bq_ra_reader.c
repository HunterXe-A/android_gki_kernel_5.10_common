// SPDX-License-Identifier: GPL-2.0
/* Read MAC (AltManufacturerAccess) commands from NFG1000B/BQ28Z610
 * without replacing its driver. Probe mode: DAStatus1 (0x0071). */
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/i2c-smbus.h>
#include <linux/i2c.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/sysfs.h>

/*
 * 设备内核 CONFIG_UBSAN=n + CONFIG_TRIM_UNUSED_KSYMS=y，未导出
 * __ubsan_handle_cfi_check_fail_abort（CFI enforcing 的失败处理函数）。
 * 编译器在受 CFI 保护的函数里会引用它，模块加载时解析不到导致
 * "Unknown symbol __ubsan_handle_cfi_check_fail_abort (err -2)"。
 * 这里在模块内自带实现，避免依赖内核导出；正常路径（CFI 检查通过）
 * 不会调用它，仅为满足链接/加载。no_sanitize("cfi") 防止该函数
 * 自身又被 CFI 检查（否则自引用死循环）。
 */
/* used 防止 LTO_FULL 将未被实际调用的 stub 当死代码剥离（剥离后
 * 符号仍是 U 引用，加载依旧失败）；no_sanitize 防止 stub 自引用。
 */
__attribute__((used, no_sanitize("cfi")))
void __ubsan_handle_cfi_check_fail_abort(void *data, void *ptr, void *vtable)
{
}

#define BQ_RA_BUS		7
#define BQ_RA_ADDR		0x55
#define BQ_RA_DRIVER_NAME	"bq28z610"
#define BQ_RA_REG_ALT_MAC	0x3e
#define BQ_RA_CMD		0x0071	/* DAStatus1: cell voltages */
#define BQ_RA_READ_LEN		36
#define BQ_RA_DATA_LEN		32

static struct i2c_client *ra_client;
static struct kobject *ra_kobj;
static DEFINE_MUTEX(ra_lock);

struct ra_find_context {
	struct i2c_client *client;
};

static int ra_find_client(struct device *dev, void *data)
{
	struct ra_find_context *context = data;
	struct i2c_client *client = i2c_verify_client(dev);

	if (!client || !client->adapter ||
		client->adapter->nr != BQ_RA_BUS || client->addr != BQ_RA_ADDR)
		return 0;
	if (!client->dev.driver ||
		strcmp(client->dev.driver->name, BQ_RA_DRIVER_NAME))
		return 0;
	if (!get_device(&client->dev))
		return 0;

	context->client = client;
	return 1;
}

static u8 ra_checksum(const u8 *data, size_t len)
{
	u16 sum = 0;
	size_t i;

	for (i = 0; i < len; i++)
		sum += data[i];

	return 0xff - (sum & 0xff);
}

static int ra_smbus_byte_data(const struct i2c_client *client, bool read,
			      u8 command, u8 *value)
{
	union i2c_smbus_data smbus_data = {};
	int ret;

	if (!read)
		smbus_data.byte = *value;

	ret = __i2c_smbus_xfer(client->adapter, client->addr, client->flags,
		read ? I2C_SMBUS_READ : I2C_SMBUS_WRITE, command,
		I2C_SMBUS_BYTE_DATA, &smbus_data);
	if (ret < 0)
		return ret;

	if (read)
		*value = smbus_data.byte;
	return 0;
}

static int ra_read_block(const struct i2c_client *client, u8 *data)
{
	u8 response[BQ_RA_READ_LEN];
	u8 value;
	u8 length;
	int ret;
	int i;

	/* Match fg_write_block(): write the MAC command to the two
	 * consecutive registers ALT_MAC (lo byte) and ALT_MAC+1 (hi byte).
	 * Writing both bytes to ALT_MAC would overwrite the first byte.
	 */
	value = BQ_RA_CMD & 0xff;
	ret = ra_smbus_byte_data(client, false, BQ_RA_REG_ALT_MAC, &value);
	if (ret)
		return ret;
	value = BQ_RA_CMD >> 8;
	ret = ra_smbus_byte_data(client, false, BQ_RA_REG_ALT_MAC + 1, &value);
	if (ret)
		return ret;

	/* Match the delay used by fg_mac_read_block(). */
	msleep(4);

	/* Match fg_read_block(): read each register separately. */
	for (i = 0; i < BQ_RA_READ_LEN; i++) {
		ret = ra_smbus_byte_data(client, true, BQ_RA_REG_ALT_MAC + i,
			&response[i]);
		if (ret)
			return ret;
	}

	length = response[BQ_RA_READ_LEN - 1];

	pr_info("bq_ra_reader: mac raw[0..35]:"
		" %02x %02x %02x %02x %02x %02x %02x %02x"
		" %02x %02x %02x %02x %02x %02x %02x %02x"
		" %02x %02x %02x %02x %02x %02x %02x %02x"
		" %02x %02x %02x %02x %02x %02x %02x %02x"
		" %02x %02x %02x %02x len=%u cksum=%02x calc=%02x\n",
		response[0], response[1], response[2], response[3],
		response[4], response[5], response[6], response[7],
		response[8], response[9], response[10], response[11],
		response[12], response[13], response[14], response[15],
		response[16], response[17], response[18], response[19],
		response[20], response[21], response[22], response[23],
		response[24], response[25], response[26], response[27],
		response[28], response[29], response[30], response[31],
		response[32], response[33], response[34], response[35],
		length, response[34], ra_checksum(response, length - 2));

	if (length < 3 || length > BQ_RA_READ_LEN)
		return -EBADMSG;
	if (ra_checksum(response, length - 2) != response[length - 2])
		return -EBADMSG;

	memcpy(data, &response[2], BQ_RA_DATA_LEN);
	return 0;
}

static ssize_t ra_table_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	u8 data[BQ_RA_DATA_LEN];
	struct i2c_client *client;
	int ret;
	int i;
	int len;

	mutex_lock(&ra_lock);
	client = ra_client;
	if (!client) {
		ret = -ENODEV;
		goto out_unlock;
	}

	/* Keep the client bound while the diagnostic transaction is in flight. */
	device_lock(&client->dev);
	if (!client->dev.driver ||
		strcmp(client->dev.driver->name, BQ_RA_DRIVER_NAME)) {
		ret = -ENODEV;
		device_unlock(&client->dev);
		goto out_unlock;
	}

	/* Hold the bus across the complete MAC command/read sequence. */
	i2c_lock_bus(client->adapter, I2C_LOCK_SEGMENT);
	ret = ra_read_block(client, data);
	i2c_unlock_bus(client->adapter, I2C_LOCK_SEGMENT);
	device_unlock(&client->dev);

out_unlock:
	mutex_unlock(&ra_lock);
	if (ret) {
		pr_err_ratelimited("bq_ra_reader: mac probe failed: %d\n", ret);
		return ret;
	}

	/* DAStatus1: data[0..1] and data[2..3] are little-endian u16 cell
	 * voltages in mV (same parse as fg_read_cell_voltage()). */
	len = sysfs_emit(buf,
		"mac_probe: cmd=0x%04x bus=%d addr=0x%02x\n"
		"cell0_mv=%u cell1_mv=%u\n",
		BQ_RA_CMD, client->adapter->nr, client->addr,
		(data[1] << 8) | data[0], (data[3] << 8) | data[2]);
	for (i = 0; i < BQ_RA_DATA_LEN; i++)
		len += sysfs_emit_at(buf, len, "%02x%c", data[i],
			i == BQ_RA_DATA_LEN - 1 ? '\n' : ' ');

	return len;
}

static struct kobj_attribute ra_table_attr = __ATTR_RO(ra_table);

static int __init bq_ra_reader_init(void)
{
	struct ra_find_context context = {};
	int ret;

	ret = i2c_for_each_dev(&context, ra_find_client);
	if (!context.client)
		return ret < 0 ? ret : -ENODEV;

	ra_client = context.client;
	ra_kobj = kobject_create_and_add("bq_ra_reader", kernel_kobj);
	if (!ra_kobj) {
		ret = -ENOMEM;
		goto put_client;
	}

	ret = sysfs_create_file(ra_kobj, &ra_table_attr.attr);
	if (ret)
		goto del_kobj;

	pr_info("bq_ra_reader: ready for %s-%04x\n",
		dev_name(&ra_client->adapter->dev), ra_client->addr);
	return 0;

del_kobj:
	kobject_put(ra_kobj);
	ra_kobj = NULL;
put_client:
	put_device(&ra_client->dev);
	ra_client = NULL;
	return ret;
}

static void __exit bq_ra_reader_exit(void)
{
	/*
	 * Stop new readers first, then wait for any in-flight show() to
	 * finish before dropping the device reference.  show() holds both
	 * ra_lock and the device lock across the whole transaction, and
	 * releases ra_lock only after device_unlock(), so taking ra_lock
	 * here after sysfs removal guarantees no reader still references
	 * ra_client.
	 */
	if (ra_kobj) {
		sysfs_remove_file(ra_kobj, &ra_table_attr.attr);
		kobject_put(ra_kobj);
		ra_kobj = NULL;
	}

	mutex_lock(&ra_lock);
	if (ra_client) {
		put_device(&ra_client->dev);
		ra_client = NULL;
	}
	mutex_unlock(&ra_lock);
}

module_init(bq_ra_reader_init);
module_exit(bq_ra_reader_exit);

MODULE_DESCRIPTION("BQ28Z610 MAC probe (DAStatus1)");
MODULE_LICENSE("GPL v2");
