// SPDX-License-Identifier: GPL-2.0
/*
 * Reusable I2C MAC (AltManufacturerAccess) read framework.
 *
 * A BQ28Z610-compatible diagnostic loader that lets the user write a MAC
 * command number into sysfs and, 5 seconds later, reads the full 36-byte
 * MACData() response. It also exposes sealed/seal nodes for type4 gauges;
 * every security-changing operation re-identifies the live gauge first.
 *
 * The CFI stub and the client lookup / device+segment bus locking are
 * intentionally kept from the BQ28Z610 probe module so this file can be
 * reused as a standalone .ko against any I2C gauge driver.
 */
#include <linux/capability.h>
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

/* BQ28Z610/NFG MAC 命令和安全状态协议。 */
#define RA_CMD_DEVICE_NAME		0x004a
#define RA_CMD_OPERATION_STATUS		0x0054
#define RA_CMD_SEAL			0x0030
#define RA_TYPE4_MODEL_LEN		8
#define RA_TYPE4_MODEL_NFG1000B	"nfg1000b"
#define RA_TYPE4_MODEL_M11R		"m11r@bm5"
#define RA_STATUS_DATA_LEN		4
#define RA_UNSEAL_KEY			0x645923cfU
#define RA_UNSEAL_KEY_XAGAPRO		0x5502020bU
#define RA_UNSEAL_RETRIES		10
#define RA_UNSEAL_FIRST_DELAY_MS	4000
#define RA_UNSEAL_SECOND_DELAY_MS	5
#define RA_SECURITY_POLL_DELAY_MS	100

/* The driver maps 0x03 to its sealed state; 0x01/0x02 are unsealed. */
#define RA_SEAL_STATE_UNSEALED_A	0x01
#define RA_SEAL_STATE_UNSEALED_B	0x02
#define RA_SEAL_STATE_SEALED		0x03

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

static int ra_write_word_locked(struct i2c_client *client, u8 command,
				 u16 value)
{
	union i2c_smbus_data smbus_data = {};
	int ret;

	if (!client)
		return -ENODEV;

	smbus_data.word = value;
	device_lock(&client->dev);
	if (!client->dev.driver ||
		strcmp(client->dev.driver->name, RA_DRIVER_NAME)) {
		device_unlock(&client->dev);
		return -ENODEV;
	}

	/* The bus is already locked, so use the non-locking SMBus primitive. */
	i2c_lock_bus(client->adapter, I2C_LOCK_SEGMENT);
	ret = __i2c_smbus_xfer(client->adapter, client->addr, client->flags,
		I2C_SMBUS_WRITE, command, I2C_SMBUS_WORD_DATA, &smbus_data);
	i2c_unlock_bus(client->adapter, I2C_LOCK_SEGMENT);
	device_unlock(&client->dev);

	return ret;
}

static u8 ra_ascii_lower(u8 value)
{
	if (value >= 'A' && value <= 'Z')
		value += 'a' - 'A';
	return value;
}

static bool ra_is_type4_model(const char *model)
{
	return !strncmp(model, RA_TYPE4_MODEL_NFG1000B,
			RA_TYPE4_MODEL_LEN) ||
		!strncmp(model, RA_TYPE4_MODEL_M11R, RA_TYPE4_MODEL_LEN);
}

/* Caller must hold ra_lock. Always identify the live gauge before use. */
static int ra_check_type4_locked(struct i2c_client *client)
{
	u8 raw[RA_READ_LEN];
	char model[RA_TYPE4_MODEL_LEN + 1];
	int ret;
	int i;

	ret = ra_read_client_command_locked(client, RA_CMD_DEVICE_NAME, raw);
	if (ret)
		return ret;

	if (raw[0] != (RA_CMD_DEVICE_NAME & 0xff) ||
		raw[1] != (RA_CMD_DEVICE_NAME >> 8) ||
		raw[RA_READ_LEN - 1] < RA_TYPE4_MODEL_LEN + 4)
		return -EBADMSG;

	for (i = 0; i < RA_TYPE4_MODEL_LEN; i++)
		model[i] = ra_ascii_lower(raw[2 + i]);
	model[RA_TYPE4_MODEL_LEN] = '\0';
	if (!ra_is_type4_model(model))
		return -EOPNOTSUPP;

	return 0;
}

/* Caller must hold ra_lock and must have checked the live model first. */
static int ra_read_sealed_locked(struct i2c_client *client, bool *sealed)
{
	u8 raw[RA_READ_LEN];
	u8 state;
	int ret;

	if (!sealed)
		return -EINVAL;

	ret = ra_read_client_command_locked(client, RA_CMD_OPERATION_STATUS, raw);
	if (ret)
		goto error;

	if (raw[0] != (RA_CMD_OPERATION_STATUS & 0xff) ||
		raw[1] != (RA_CMD_OPERATION_STATUS >> 8) ||
		raw[RA_READ_LEN - 1] < RA_STATUS_DATA_LEN + 4) {
		ret = -EBADMSG;
		goto error;
	}

	/* 与原 gauge 驱动一致：检查 payload byte 1，即 raw[3]。 */
	state = raw[3] & 0x03;
	/* 原驱动将 raw=0x03 映射为内部 seal_state=2（sealed）；
	 * raw=0x01/0x02 都是未封存分支。 */
	if (state == RA_SEAL_STATE_SEALED) {
		*sealed = true;
	} else if (state == RA_SEAL_STATE_UNSEALED_A ||
			state == RA_SEAL_STATE_UNSEALED_B) {
		*sealed = false;
	} else {
		ret = -EIO;
		goto error;
	}

	return 0;

error:
	return ret;
}

/*
 * get_hw_sku 由 hwid 模块导出；CI 纯模块构建时符号不可见，声明为弱符号，
 * 设备加载时由模块加载器解析，解析不到则回退普通 type4 key。
 */
extern const char *get_hw_sku(void) __weak;

static u32 ra_unseal_key(void)
{
	const char *sku;

	/* CI 纯模块构建下弱符号未解析，地址为 0 时回退普通 type4 key。 */
	if (get_hw_sku == NULL)
		return RA_UNSEAL_KEY;

	sku = get_hw_sku();
	if (sku && strncmp(sku, "xagapro", strlen("xagapro")) == 0)
		return RA_UNSEAL_KEY_XAGAPRO;
	return RA_UNSEAL_KEY;
}

/* 调用者须持有 ra_lock；type4 的 key 顺序为 low-low-high。 */
static int ra_send_unseal_key_locked(struct i2c_client *client, u32 key)
{
	int ret;

	ret = ra_write_word_locked(client, RA_REG_ALT_MAC, key & 0xffff);
	if (ret)
		return ret;
	msleep(RA_UNSEAL_FIRST_DELAY_MS);

	ret = ra_write_word_locked(client, RA_REG_ALT_MAC, key & 0xffff);
	if (ret)
		return ret;
	msleep(RA_UNSEAL_SECOND_DELAY_MS);

	return ra_write_word_locked(client, RA_REG_ALT_MAC, key >> 16);
}

/* 调用者须持有 ra_lock；返回 0 表示目标状态已验证。 */
static int ra_set_sealed_locked(struct i2c_client *client, bool want_sealed)
{
	bool sealed;
	u32 key;
	int attempt;
	int ret = -ETIMEDOUT;

	ret = ra_check_type4_locked(client);
	if (ret)
		return ret;
	ret = ra_read_sealed_locked(client, &sealed);
	if (ret)
		return ret;
	if (sealed == want_sealed)
		return 0;

	key = ra_unseal_key();
	for (attempt = 0; attempt < RA_UNSEAL_RETRIES; attempt++) {
		/* Re-check immediately before every security-changing transaction. */
		ret = ra_check_type4_locked(client);
		if (ret)
			break;

		if (want_sealed)
			ret = ra_write_word_locked(client, RA_REG_ALT_MAC,
						  RA_CMD_SEAL);
		else
			ret = ra_send_unseal_key_locked(client, key);
		if (ret) {
			pr_err_ratelimited("raR: %s command failed attempt=%d ret=%d\n",
				want_sealed ? "seal" : "unseal", attempt + 1, ret);
			msleep(RA_SECURITY_POLL_DELAY_MS);
			continue;
		}

		/* Match the gauge driver: allow the security state to settle. */
		msleep(RA_SECURITY_POLL_DELAY_MS);
		if (!want_sealed)
			msleep(RA_SECURITY_POLL_DELAY_MS);

		ret = ra_check_type4_locked(client);
		if (ret)
			break;
		ret = ra_read_sealed_locked(client, &sealed);
		if (!ret && sealed == want_sealed)
			return 0;
		if (!ret)
			ret = -EAGAIN;
	}

	pr_err("raR: failed to %s type4 gauge after %d attempts, ret=%d\n",
		want_sealed ? "seal" : "unseal", attempt, ret);
	return ret;
}

static ssize_t ra_show_sealed(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	bool sealed;
	int ret;

	mutex_lock(&ra_lock);
	if (ra_stopping || !ra_client) {
		ret = -ENODEV;
	} else {
		ret = ra_check_type4_locked(ra_client);
		if (!ret)
			ret = ra_read_sealed_locked(ra_client, &sealed);
	}
	mutex_unlock(&ra_lock);

	if (ret) {
		pr_err_ratelimited("raR: sealed read failed: %d\n", ret);
		return ret;
	}
	return sysfs_emit(buf, "%u\n", sealed ? 1 : 0);
}

static ssize_t ra_store_seal(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	unsigned int value;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = kstrtouint(buf, 0, &value);
	if (ret || value > 1)
		return -EINVAL;

	mutex_lock(&ra_lock);
	if (ra_stopping || !ra_client)
		ret = -ENODEV;
	else
		ret = ra_set_sealed_locked(ra_client, value == 1);
	mutex_unlock(&ra_lock);

	if (ret)
		return ret;
	return count;
}

static struct kobj_attribute ra_sealed_attr =
	__ATTR(sealed, 0444, ra_show_sealed, NULL);
static struct kobj_attribute ra_seal_attr =
	__ATTR(seal, 0600, ra_show_sealed, ra_store_seal);

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

	ret = sysfs_create_file(ra_kobj, &ra_sealed_attr.attr);
	if (ret)
		goto remove_result;

	ret = sysfs_create_file(ra_kobj, &ra_seal_attr.attr);
	if (ret)
		goto remove_sealed;

	pr_info("raR: ready for %s-%04x, read delay=%ums, type4 security nodes enabled\n",
		dev_name(&ra_client->adapter->dev), ra_client->addr,
		RA_WRITE_TO_READ_DELAY_MS);
	return 0;

remove_sealed:
	sysfs_remove_file(ra_kobj, &ra_sealed_attr.attr);
remove_result:
	sysfs_remove_file(ra_kobj, &ra_result_attr.attr);
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
		sysfs_remove_file(ra_kobj, &ra_seal_attr.attr);
		sysfs_remove_file(ra_kobj, &ra_sealed_attr.attr);
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

MODULE_DESCRIPTION("Reusable I2C MAC read framework with type4 security control");
MODULE_LICENSE("GPL v2");
