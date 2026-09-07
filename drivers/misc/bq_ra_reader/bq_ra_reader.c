// SPDX-License-Identifier: GPL-2.0
/* Read MAC (AltManufacturerAccess) commands from NFG1000B/BQ28Z610
 * without replacing its driver. Probe mode: GaugingStatus + CompRes capture. */
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

#define BQ_RA_BUS			7
#define BQ_RA_ADDR			0x55
#define BQ_RA_DRIVER_NAME		"bq28z610"
#define BQ_RA_REG_ALT_MAC		0x3e
#define BQ_RA_CMD_GAUGING_STATUS	0x0056
#define BQ_RA_CMD_IT_STATUS1		0x0073
#define BQ_RA_READ_LEN			36

/*
 * GaugingStatus() 的实测响应是 response[2..5] 四字节数据：日志中的
 * length=0x08 表示 checksum 覆盖 response[0..5]，即命令回显 2 字节加
 * 状态数据 4 字节。保留完整 32 位状态才能表示 RX(bit18)。
 */
#define BQ_RA_GAUGING_DATA_LEN		4
#define BQ_RA_IT_STATUS1_DATA_LEN	20
#define BQ_RA_COMP_RES_OFFSET		18
#define BQ_RA_MIN_POLL_INTERVAL_MS	100U

/* 可在 insmod 时设置，也可通过 /sys/module/bq_ra_reader/parameters/ 修改。 */
static unsigned int poll_interval_ms = 5000;
module_param(poll_interval_ms, uint, 0644);
MODULE_PARM_DESC(poll_interval_ms,
	"GaugingStatus polling interval in milliseconds (minimum 100)");

/*
 * GaugingStatus() 关键位。
 *
 * 这些位号按当前 BQ28Z610 实测协议使用：RX 位位于 32 位状态的 bit18，
 * 因此不能再用 u16 保存状态。RX 翻转是一次 Ra/CompRes 更新事件的触发
 * 条件；VOK、REST、DSG 作为事件发生时的上下文一起保存。
 */
#define GAUGING_STATUS_R_DIS	BIT(10)
#define GAUGING_STATUS_VOK	BIT(11)
#define GAUGING_STATUS_RX	BIT(18)
#define GAUGING_STATUS_REST	BIT(8)
#define GAUGING_STATUS_DSG	BIT(6)

static struct i2c_client *ra_client;
static struct kobject *ra_kobj;
static DEFINE_MUTEX(ra_lock);
static struct delayed_work ra_poll_work;

/* All fields below are protected by ra_lock. */
static bool ra_stopping;
static bool ra_rx_valid;
static u32 ra_rx_last;
static u32 ra_last_gauging_status;
static bool ra_have_comp_res;
static u16 ra_comp_res_raw;
static u32 ra_comp_res_mohm_x10;
static u32 ra_comp_capture_count;
static unsigned long ra_comp_timestamp;
static u32 ra_comp_gauging_status;
static bool ra_comp_context_vok_rest;

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

static u32 ra_status_value(const u8 *data)
{
	return (u32)data[0] | ((u32)data[1] << 8) |
		((u32)data[2] << 16) | ((u32)data[3] << 24);
}

static unsigned int ra_effective_poll_interval_ms(void)
{
	return max(poll_interval_ms, BQ_RA_MIN_POLL_INTERVAL_MS);
}

static unsigned long ra_poll_delay(void)
{
	return msecs_to_jiffies(ra_effective_poll_interval_ms());
}

/* Return tenths of a milliohm: raw * 1000 / 1024 milliohm, x10 fixed point. */
static u32 ra_comp_res_to_mohm_x10(u16 raw)
{
	return ((u32)raw * 1000U * 10U) / 1024U;
}

/*
 * Execute one MAC read while the caller holds ra_lock. The gauge keeps the
 * checksum byte at response[34] and the length at response[35]; length-2 is
 * the number of leading bytes covered by the checksum, matching the official
 * fg_mac_read_block() implementation.
 */
static int ra_read_mac_block(const struct i2c_client *client, u16 cmd,
			     u8 *data, u8 data_len)
{
	u8 response[BQ_RA_READ_LEN];
	u8 value;
	u8 length;
	u8 checksum;
	int ret;
	int i;

	if (!data || !data_len || data_len > BQ_RA_READ_LEN - 4)
		return -EINVAL;

	value = cmd & 0xff;
	ret = ra_smbus_byte_data(client, false, BQ_RA_REG_ALT_MAC, &value);
	if (ret)
		return ret;
	value = cmd >> 8;
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
	if (length < 3 || length > BQ_RA_READ_LEN ||
		length < data_len + 4) {
		pr_err_ratelimited("bq_ra_reader: invalid MAC response cmd=0x%04x len=%u data_len=%u\n",
			cmd, length, data_len);
		return -EBADMSG;
	}

	checksum = ra_checksum(response, length - 2);
	pr_info_ratelimited("bq_ra_reader: cmd=0x%04x mac raw[0..35]:"
		" %02x %02x %02x %02x %02x %02x %02x %02x"
		" %02x %02x %02x %02x %02x %02x %02x %02x"
		" %02x %02x %02x %02x %02x %02x %02x %02x"
		" %02x %02x %02x %02x %02x %02x %02x %02x"
		" %02x %02x %02x %02x len=%u cksum=%02x calc=%02x\n",
		cmd,
		response[0], response[1], response[2], response[3],
		response[4], response[5], response[6], response[7],
		response[8], response[9], response[10], response[11],
		response[12], response[13], response[14], response[15],
		response[16], response[17], response[18], response[19],
		response[20], response[21], response[22], response[23],
		response[24], response[25], response[26], response[27],
		response[28], response[29], response[30], response[31],
		response[32], response[33], response[34], response[35],
		length, response[34], checksum);

	if (checksum != response[34])
		return -EBADMSG;

	memcpy(data, &response[2], data_len);
	return 0;
}

/* Caller must hold ra_lock. */
static int ra_read_client_command_locked(const struct i2c_client *client,
					 u16 cmd, u8 *data, u8 data_len)
{
	int ret;

	if (!client)
		return -ENODEV;

	/* Keep the client bound while the diagnostic transaction is in flight. */
	device_lock(&client->dev);
	if (!client->dev.driver ||
		strcmp(client->dev.driver->name, BQ_RA_DRIVER_NAME)) {
		device_unlock(&client->dev);
		return -ENODEV;
	}

	/* Hold the bus across the complete MAC command/read sequence. */
	i2c_lock_bus(client->adapter, I2C_LOCK_SEGMENT);
	ret = ra_read_mac_block(client, cmd, data, data_len);
	i2c_unlock_bus(client->adapter, I2C_LOCK_SEGMENT);
	device_unlock(&client->dev);

	return ret;
}

static int ra_prime_rx_baseline_locked(void)
{
	u8 data[BQ_RA_GAUGING_DATA_LEN];
	u32 status;
	int ret;

	ret = ra_read_client_command_locked(ra_client,
		BQ_RA_CMD_GAUGING_STATUS, data, sizeof(data));
	if (ret)
		return ret;

	status = ra_status_value(data);
	ra_last_gauging_status = status;
	ra_rx_last = status & GAUGING_STATUS_RX;
	ra_rx_valid = true;
	pr_info("bq_ra_reader: RX baseline=0x%08x GaugingStatus=0x%08x\n",
		ra_rx_last, status);
	return 0;
}

static void ra_poll_workfn(struct work_struct *work)
{
	u8 gauging_data[BQ_RA_GAUGING_DATA_LEN];
	u8 it_status_data[BQ_RA_IT_STATUS1_DATA_LEN];
	u32 status;
	u32 rx_now;
	u16 comp_res;
	bool rx_changed;
	bool context_vok_rest;
	int ret;

	(void)work;
	mutex_lock(&ra_lock);
	if (ra_stopping || !ra_client)
		goto reschedule;

	ret = ra_read_client_command_locked(ra_client,
		BQ_RA_CMD_GAUGING_STATUS, gauging_data, sizeof(gauging_data));
	if (ret) {
		pr_err_ratelimited("bq_ra_reader: GaugingStatus poll failed: %d\n",
			ret);
		goto reschedule;
	}

	status = ra_status_value(gauging_data);
	ra_last_gauging_status = status;
	rx_now = status & GAUGING_STATUS_RX;
	if (!ra_rx_valid) {
		/* A failed startup read has no baseline; the first good poll only
		 * establishes one and must not be reported as an update event. */
		ra_rx_last = rx_now;
		ra_rx_valid = true;
		goto reschedule;
	}

	rx_changed = rx_now != ra_rx_last;
	if (!rx_changed)
		goto reschedule;

	/* RX is the event edge. VOK and REST explain the event context, but are
	 * not used as a gate: they can clear before this periodic sample arrives.
	 * Rejecting the edge here could lose a real CompRes update permanently. */
	context_vok_rest = !!(status & GAUGING_STATUS_VOK) &&
		!!(status & GAUGING_STATUS_REST);
	ret = ra_read_client_command_locked(ra_client,
		BQ_RA_CMD_IT_STATUS1, it_status_data, sizeof(it_status_data));
	if (ret) {
		pr_err_ratelimited("bq_ra_reader: ITStatus1 read after RX change failed: %d\n",
			ret);
		/* Keep the old baseline so the same edge is retried next poll. */
		goto reschedule;
	}

	comp_res = (u16)it_status_data[BQ_RA_COMP_RES_OFFSET] |
		((u16)it_status_data[BQ_RA_COMP_RES_OFFSET + 1] << 8);
	ra_rx_last = rx_now;
	ra_comp_res_raw = comp_res;
	ra_comp_res_mohm_x10 = ra_comp_res_to_mohm_x10(comp_res);
	ra_comp_capture_count++;
	ra_comp_timestamp = jiffies;
	ra_comp_gauging_status = status;
	ra_comp_context_vok_rest = context_vok_rest;
	ra_have_comp_res = true;
	pr_info("bq_ra_reader: captured CompRes raw=%u mOhm=%u.%u "
		"status=0x%08x VOK=%u REST=%u DSG=%u context_vok_rest=%u count=%u\n",
		comp_res, ra_comp_res_mohm_x10 / 10,
		ra_comp_res_mohm_x10 % 10, status,
		!!(status & GAUGING_STATUS_VOK),
		!!(status & GAUGING_STATUS_REST),
		!!(status & GAUGING_STATUS_DSG),
		context_vok_rest, ra_comp_capture_count);

reschedule:
	if (!ra_stopping)
		schedule_delayed_work(&ra_poll_work, ra_poll_delay());
	mutex_unlock(&ra_lock);
}

static ssize_t ra_table_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	u8 data[BQ_RA_GAUGING_DATA_LEN];
	struct i2c_client *client;
	u32 flags;
	int adapter_nr;
	int addr;
	int ret;
	int i;
	int len;

	mutex_lock(&ra_lock);
	client = ra_client;
	if (!client) {
		ret = -ENODEV;
		goto out_unlock;
	}

	ret = ra_read_client_command_locked(client,
		BQ_RA_CMD_GAUGING_STATUS, data, sizeof(data));
	if (ret)
		goto out_unlock;

	adapter_nr = client->adapter->nr;
	addr = client->addr;
	flags = ra_status_value(data);
	ra_last_gauging_status = flags;

out_unlock:
	mutex_unlock(&ra_lock);
	if (ret) {
		pr_err_ratelimited("bq_ra_reader: GaugingStatus read failed: %d\n",
			ret);
		return ret;
	}

	len = sysfs_emit(buf,
		"mac_probe: cmd=0x%04x bus=%d addr=0x%02x\n"
		"gauging_status=0x%08x\n"
		"R_DIS=%u VOK=%u RX=%u REST=%u DSG=%u\n",
		BQ_RA_CMD_GAUGING_STATUS, adapter_nr, addr, flags,
		!!(flags & GAUGING_STATUS_R_DIS),
		!!(flags & GAUGING_STATUS_VOK),
		!!(flags & GAUGING_STATUS_RX),
		!!(flags & GAUGING_STATUS_REST),
		!!(flags & GAUGING_STATUS_DSG));
	for (i = 0; i < BQ_RA_GAUGING_DATA_LEN; i++)
		len += sysfs_emit_at(buf, len, "%02x%c", data[i],
			i == BQ_RA_GAUGING_DATA_LEN - 1 ? '\n' : ' ');

	return len;
}

static ssize_t ra_comp_res_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	unsigned int interval_ms;
	unsigned int effective_ms;
	ssize_t len;

	mutex_lock(&ra_lock);
	interval_ms = poll_interval_ms;
	effective_ms = ra_effective_poll_interval_ms();
	if (!ra_have_comp_res) {
		len = sysfs_emit(buf,
			"status=not_captured\n"
			"message=valid_comp_res_update_not_captured\n"
			"poll_interval_ms=%u\n"
			"poll_interval_effective_ms=%u\n"
			"rx_baseline_valid=%u\n"
			"last_gauging_status=0x%08x\n"
			"capture_count=0\n",
			interval_ms, effective_ms, ra_rx_valid,
			ra_last_gauging_status);
	} else {
		len = sysfs_emit(buf,
			"status=valid\n"
			"comp_res_raw=%u\n"
			"comp_res_mohm_x10=%u\n"
			"comp_res_mohm=%u.%u\n"
			"capture_timestamp_jiffies=%lu\n"
			"capture_count=%u\n"
			"capture_gauging_status=0x%08x\n"
			"capture_R_DIS=%u capture_VOK=%u capture_RX=%u "
			"capture_REST=%u capture_DSG=%u\n"
			"capture_VOK_REST=%u\n"
			"poll_interval_ms=%u\n"
			"poll_interval_effective_ms=%u\n",
			ra_comp_res_raw, ra_comp_res_mohm_x10,
			ra_comp_res_mohm_x10 / 10,
			ra_comp_res_mohm_x10 % 10,
			ra_comp_timestamp, ra_comp_capture_count,
			ra_comp_gauging_status,
			!!(ra_comp_gauging_status & GAUGING_STATUS_R_DIS),
			!!(ra_comp_gauging_status & GAUGING_STATUS_VOK),
			!!(ra_comp_gauging_status & GAUGING_STATUS_RX),
			!!(ra_comp_gauging_status & GAUGING_STATUS_REST),
			!!(ra_comp_gauging_status & GAUGING_STATUS_DSG),
			ra_comp_context_vok_rest, interval_ms, effective_ms);
	}
	mutex_unlock(&ra_lock);
	return len;
}

static struct kobj_attribute ra_table_attr = __ATTR_RO(ra_table);
static struct kobj_attribute ra_comp_res_attr = __ATTR_RO(comp_res);

static int __init bq_ra_reader_init(void)
{
	struct ra_find_context context = {};
	int ret;

	INIT_DELAYED_WORK(&ra_poll_work, ra_poll_workfn);
	ra_stopping = false;

	ret = i2c_for_each_dev(&context, ra_find_client);
	if (!context.client)
		return ret < 0 ? ret : -ENODEV;

	ra_client = context.client;
	mutex_lock(&ra_lock);
	ret = ra_prime_rx_baseline_locked();
	mutex_unlock(&ra_lock);
	if (ret)
		pr_warn("bq_ra_reader: initial GaugingStatus read failed: %d; "
			"first successful poll will establish RX baseline\n", ret);

	ra_kobj = kobject_create_and_add("bq_ra_reader", kernel_kobj);
	if (!ra_kobj) {
		ret = -ENOMEM;
		goto put_client;
	}

	ret = sysfs_create_file(ra_kobj, &ra_table_attr.attr);
	if (ret)
		goto del_kobj;

	ret = sysfs_create_file(ra_kobj, &ra_comp_res_attr.attr);
	if (ret)
		goto remove_table;

	pr_info("bq_ra_reader: ready for %s-%04x, poll_interval=%ums\n",
		dev_name(&ra_client->adapter->dev), ra_client->addr,
		ra_effective_poll_interval_ms());
	schedule_delayed_work(&ra_poll_work, ra_poll_delay());
	return 0;

remove_table:
	sysfs_remove_file(ra_kobj, &ra_table_attr.attr);
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
	/* Prevent the worker from scheduling another round, then wait for any
	 * in-flight I2C transaction before dropping the client reference. */
	mutex_lock(&ra_lock);
	ra_stopping = true;
	mutex_unlock(&ra_lock);
	cancel_delayed_work_sync(&ra_poll_work);

	if (ra_kobj) {
		sysfs_remove_file(ra_kobj, &ra_comp_res_attr.attr);
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

MODULE_DESCRIPTION("BQ28Z610 GaugingStatus RX-linked CompRes probe");
MODULE_LICENSE("GPL v2");
