// SPDX-License-Identifier: GPL-2.0
/*
 * Reusable I2C MAC (AltManufacturerAccess) read framework.
 *
 * A generic, chip-agnostic loader that lets the user write a MAC command
 * number into sysfs and, 5 seconds later, reads the full 36-byte MACData()
 * response into a read-only sysfs node. No BQ28Z610-specific field parsing
 * or analysis is performed here; this is the raw MAC read framework only.
 *
 * The CFI stub and the client lookup / device+segment bus locking are
 * intentionally kept from the BQ28Z610 probe module so this file can be
 * reused as a standalone .ko against any I2C gauge driver.
 */
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/i2c-smbus.h>
#include <linux/i2c.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/workqueue.h>

/*
 * 设备内核 CONFIG_UBSAN=n + CONFIG_TRIM_UNUSED_KSYMS=y，未导出
 * __ubsan_handle_cfi_check_fail_abort（CFI enforcing 的失败处理函数）。
 * 这里在模块内自带实现，避免依赖内核导出；正常路径（CFI 检查通过）
 * 不会调用它，仅为满足链接/加载。no_sanitize("cfi") 防止该函数
 * 自身又被 CFI 检查（否则自引用死循环）。
 */
__attribute__((used, no_sanitize("cfi")))
void __ubsan_handle_cfi_check_fail_abort(void *data, void *ptr, void *vtable)
{
}

/* 目标 I2C client 平台参数（可改，框架查找用）。 */
#define RA_BUS				7
#define RA_ADDR				0x55
#define RA_DRIVER_NAME			"bq28z610"

#define RA_REG_ALT_MAC			0x3e
#define RA_READ_LEN			36
#define RA_WRITE_TO_READ_DELAY_MS	5000

static struct i2c_client *ra_client;
static struct kobject *ra_kobj;
static DEFINE_MUTEX(ra_lock);
static struct delayed_work ra_work;

/* 以下字段均由 ra_lock 保护。 */
static bool ra_stopping;
static u16 ra_cmd;
static bool ra_result_valid;
static int ra_result_error;
static u8 ra_result_raw[RA_READ_LEN];
static unsigned long ra_result_timestamp;

struct ra_find_context {
	struct i2c_client *client;
};

static int ra_find_client(struct device *dev, void *data)
{
	struct ra_find_context *context = data;
	struct i2c_client *client = i2c_verify_client(dev);

	if (!client || !client->adapter ||
		client->adapter->nr != RA_BUS || client->addr != RA_ADDR)
		return 0;
	if (!client->dev.driver ||
		strcmp(client->dev.driver->name, RA_DRIVER_NAME))
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

/*
 * Read one MAC command. Caller must hold ra_lock. Writes the command number
 * to AltManufacturerAccess (0x3E/0x3F), waits, then reads the fixed 36-byte
 * MACData window. The checksum byte is kept at response[34] and the length at
 * response[35], matching the official fg_mac_read_block() implementation.
 */
static int ra_read_mac_block(const struct i2c_client *client, u16 cmd,
			     u8 *raw_response)
{
	u8 response[RA_READ_LEN];
	u8 value;
	u8 length;
	u8 checksum;
	int ret;
	int i;

	if (!raw_response)
		return -EINVAL;

	value = cmd & 0xff;
	ret = ra_smbus_byte_data(client, false, RA_REG_ALT_MAC, &value);
	if (ret)
		return ret;
	value = cmd >> 8;
	ret = ra_smbus_byte_data(client, false, RA_REG_ALT_MAC + 1, &value);
	if (ret)
		return ret;

	/* Match the delay used by fg_mac_read_block(). */
	msleep(4);

	/* Read each register separately, matching fg_read_block(). */
	for (i = 0; i < RA_READ_LEN; i++) {
		ret = ra_smbus_byte_data(client, true, RA_REG_ALT_MAC + i,
			&response[i]);
		if (ret)
			return ret;
	}

	length = response[RA_READ_LEN - 1];
	if (length < 3 || length > RA_READ_LEN) {
		pr_err("raR: invalid MAC response cmd=0x%04x len=%u\n", cmd,
			length);
		return -EBADMSG;
	}

	checksum = ra_checksum(response, length - 2);
	if (checksum != response[RA_READ_LEN - 2]) {
		pr_err("raR: MAC checksum mismatch cmd=0x%04x\n", cmd);
		return -EBADMSG;
	}

	memcpy(raw_response, response, RA_READ_LEN);
	return 0;
}

/* Caller must hold ra_lock. */
static int ra_read_client_command_locked(struct i2c_client *client, u16 cmd,
					 u8 *raw_response)
{
	int ret;

	if (!client)
		return -ENODEV;

	/* Keep the client bound while the transaction is in flight. */
	device_lock(&client->dev);
	if (!client->dev.driver ||
		strcmp(client->dev.driver->name, RA_DRIVER_NAME)) {
		device_unlock(&client->dev);
		return -ENODEV;
	}

	/* Hold the bus across the complete MAC command/read sequence. */
	i2c_lock_bus(client->adapter, I2C_LOCK_SEGMENT);
	ret = ra_read_mac_block(client, cmd, raw_response);
	i2c_unlock_bus(client->adapter, I2C_LOCK_SEGMENT);
	device_unlock(&client->dev);

	return ret;
}

static void ra_workfn(struct work_struct *work)
{
	int ret;

	(void)work;
	mutex_lock(&ra_lock);
	if (ra_stopping || !ra_client)
		goto out;

	ret = ra_read_client_command_locked(ra_client, ra_cmd, ra_result_raw);
	ra_result_error = ret;
	ra_result_valid = true;
	ra_result_timestamp = jiffies;

out:
	mutex_unlock(&ra_lock);
}

static ssize_t ra_store_cmd(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	u16 cmd;
	int ret;
	int parsed;

	ret = sscanf(buf, "%i", &parsed);
	if (ret != 1 || parsed < 0 || parsed > 0xffff)
		return -EINVAL;
	cmd = (u16)parsed;

	mutex_lock(&ra_lock);
	if (ra_stopping || !ra_client) {
		mutex_unlock(&ra_lock);
		return -ENODEV;
	}
	ra_cmd = cmd;
	ra_result_valid = false;
	ra_result_error = 0;
	mod_delayed_work(system_wq, &ra_work,
		msecs_to_jiffies(RA_WRITE_TO_READ_DELAY_MS));
	mutex_unlock(&ra_lock);

	return count;
}

static ssize_t ra_show_result(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	u8 raw[RA_READ_LEN];
	ssize_t len;
	bool valid;
	u16 cmd;
	int error;
	unsigned long timestamp;
	int i;

	mutex_lock(&ra_lock);
	valid = ra_result_valid;
	cmd = ra_cmd;
	error = ra_result_error;
	timestamp = ra_result_timestamp;
	memcpy(raw, ra_result_raw, RA_READ_LEN);
	mutex_unlock(&ra_lock);

	if (!valid)
		return sysfs_emit(buf, "status=pending\ncommand=0x%04x\n", cmd);

	if (error)
		return sysfs_emit(buf, "status=error\ncommand=0x%04x\n"
			"read_error=%d\ntimestamp_jiffies=%lu\n", cmd, error,
			timestamp);

	len = sysfs_emit(buf,
		"status=done\n"
		"command=0x%04x\n"
		"raw_response[0..35]=", cmd);
	for (i = 0; i < RA_READ_LEN; i++)
		len += sysfs_emit_at(buf, len, "%s%02x", i ? " " : "",
			raw[i]);
	len += sysfs_emit_at(buf, len, "\n");
	len += sysfs_emit_at(buf, len, "command_echo=%02x %02x\n",
		raw[0], raw[1]);
	len += sysfs_emit_at(buf, len, "response_checksum_byte=%02x\n",
		raw[RA_READ_LEN - 2]);
	len += sysfs_emit_at(buf, len, "response_length_byte=%u\n",
		raw[RA_READ_LEN - 1]);
	len += sysfs_emit_at(buf, len, "timestamp_jiffies=%lu\n", timestamp);

	return len;
}

static struct kobj_attribute ra_store_attr =
	__ATTR(mac_cmd, 0200, NULL, ra_store_cmd);
static struct kobj_attribute ra_result_attr =
	__ATTR(mac_result, 0444, ra_show_result, NULL);

static int __init ra_init(void)
{
	struct ra_find_context context = {};
	int ret;

	INIT_DELAYED_WORK(&ra_work, ra_workfn);
	ra_stopping = false;

	ret = i2c_for_each_dev(&context, ra_find_client);
	if (!context.client)
		return ret < 0 ? ret : -ENODEV;

	ra_client = context.client;
	ra_kobj = kobject_create_and_add("raR", kernel_kobj);
	if (!ra_kobj) {
		ret = -ENOMEM;
		goto put_client;
	}

	ret = sysfs_create_file(ra_kobj, &ra_store_attr.attr);
	if (ret)
		goto del_kobj;

	ret = sysfs_create_file(ra_kobj, &ra_result_attr.attr);
	if (ret)
		goto remove_store;

	pr_info("raR: ready for %s-%04x, read delay=%ums\n",
		dev_name(&ra_client->adapter->dev), ra_client->addr,
		RA_WRITE_TO_READ_DELAY_MS);
	return 0;

remove_store:
	sysfs_remove_file(ra_kobj, &ra_store_attr.attr);
del_kobj:
	kobject_put(ra_kobj);
	ra_kobj = NULL;
put_client:
	put_device(&ra_client->dev);
	ra_client = NULL;
	return ret;
}

static void __exit ra_exit(void)
{
	mutex_lock(&ra_lock);
	ra_stopping = true;
	mutex_unlock(&ra_lock);
	cancel_delayed_work_sync(&ra_work);

	if (ra_kobj) {
		sysfs_remove_file(ra_kobj, &ra_result_attr.attr);
		sysfs_remove_file(ra_kobj, &ra_store_attr.attr);
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

module_init(ra_init);
module_exit(ra_exit);

MODULE_DESCRIPTION("Reusable I2C MAC read framework");
MODULE_LICENSE("GPL v2");