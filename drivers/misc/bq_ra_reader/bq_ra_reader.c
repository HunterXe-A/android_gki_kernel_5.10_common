// SPDX-License-Identifier: GPL-2.0
/* Read MAC (AltManufacturerAccess) commands from NFG1000B/BQ28Z610
 * without replacing its driver. Probe mode: GaugingStatus + ITStatus1/2. */
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
#define BQ_RA_CMD_IT_STATUS2		0x0074
#define BQ_RA_READ_LEN			36

/* ITStatus2 response[2..5]: Pack Grid, LStatus, Cell Grid1, Cell Grid2. */
#define BQ_RA_IT_STATUS2_DATA_LEN	4
#define BQ_RA_IT_STATUS2_PACK_GRID_OFFSET	0
#define BQ_RA_IT_STATUS2_LSTATUS_OFFSET	1
#define BQ_RA_IT_STATUS2_CELL_GRID1_OFFSET	2
#define BQ_RA_IT_STATUS2_CELL_GRID2_OFFSET	3

/* LStatus: bit3=QMax, bit2=ITEN, bit1=CF1, bit0=CF0. */
#define IT_STATUS2_LSTATUS_CF0		BIT(0)
#define IT_STATUS2_LSTATUS_CF1		BIT(1)
#define IT_STATUS2_LSTATUS_ITEN		BIT(2)
#define IT_STATUS2_LSTATUS_QMAX		BIT(3)

/*
 * GaugingStatus() 的实测响应是 response[2..5] 四字节数据：日志中的
 * length=0x08 表示 checksum 覆盖 response[0..5]，即命令回显 2 字节加
 * 状态数据 4 字节。保留完整 32 位状态才能表示 RX(bit18)。
 */
#define BQ_RA_GAUGING_DATA_LEN		4
#define BQ_RA_IT_STATUS1_DATA_LEN	24
#define BQ_RA_IT_TRUE_REM_Q_OFFSET	0
#define BQ_RA_IT_TRUE_REM_E_OFFSET	2
#define BQ_RA_IT_INITIAL_Q_OFFSET	4
#define BQ_RA_IT_INITIAL_E_OFFSET	6
#define BQ_RA_IT_TRUE_FULL_CHG_Q_OFFSET	8
#define BQ_RA_IT_TRUE_FULL_CHG_E_OFFSET	10
#define BQ_RA_IT_T_SIM_OFFSET		12
#define BQ_RA_IT_T_AMBIENT_OFFSET	14
#define BQ_RA_IT_RA_SCALE0_OFFSET	16
#define BQ_RA_IT_RA_SCALE1_OFFSET	18
#define BQ_RA_IT_COMP_RES1_OFFSET	20
#define BQ_RA_IT_COMP_RES2_OFFSET	22
#define BQ_RA_MIN_POLL_INTERVAL_MS	100U

/* 可在 insmod 时设置，也可通过 /sys/module/bq_ra_reader/parameters/ 修改。 */
static unsigned int poll_interval_ms = 5000;
module_param(poll_interval_ms, uint, 0644);
MODULE_PARM_DESC(poll_interval_ms,
	"ITStatus1 polling interval in milliseconds (minimum 100)");

/* GaugingStatus() 关键位，仅用于诊断展示，不参与 CompRes 捕获触发。 */
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
static u32 ra_last_gauging_status;
static bool ra_it_status2_valid;
static u8 ra_it_status2_pack_grid;
static u8 ra_it_status2_lstatus;
static u8 ra_it_status2_cell_grid1;
static u8 ra_it_status2_cell_grid2;
static int ra_it_status2_last_error;
static unsigned long ra_it_status2_timestamp;
static bool ra_it_baseline_valid;
static s16 ra_it_last_comp_res1;
static s16 ra_it_last_comp_res2;
static bool ra_have_comp_res;
static s16 ra_comp_res1_raw;
static s16 ra_comp_res2_raw;
static s16 ra_comp_ra_scale0;
static s16 ra_comp_ra_scale1;
static bool ra_comp_cell1_valid;
static bool ra_comp_cell2_valid;
static s32 ra_comp_cell1_mohm_x10;
static s32 ra_comp_cell2_mohm_x10;
static u32 ra_comp_capture_count;
static unsigned long ra_comp_timestamp;

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

static u16 ra_le16(const u8 *data, unsigned int offset)
{
	return (u16)data[offset] | ((u16)data[offset + 1] << 8);
}

static s16 ra_sle16(const u8 *data, unsigned int offset)
{
	return (s16)ra_le16(data, offset);
}

/*
 * 返回 x10 毫欧值：raw / scale * 1000 / 1024 * 10。
 * 先乘 10000，再除以 scale*1024，保留一位小数；s64 同时保证
 * 中间结果和负值都不会溢出。scale 为 0 时返回 false，表示不可用。
 */
static bool ra_comp_res_to_mohm_x10(s16 raw, u16 scale, s32 *result)
{
	s64 numerator;
	s64 denominator;

	if (!scale || !result)
		return false;

	numerator = (s64)raw * 10000;
	denominator = (s64)scale * 1024;
	*result = (s32)(numerator / denominator);
	return true;
}

static bool ra_is_single_cell_hint(s16 scale0, s16 scale1)
{
	/* 两个 scale 都为正且 scale1 小于 scale0 的十分之一时，提示 Cell2 可能是占位字段。 */
	return scale0 > 0 && scale1 >= 0 && scale1 < scale0 / 10;
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
static int ra_read_client_command_locked(struct i2c_client *client,
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

/* Caller must hold ra_lock. */
static int ra_read_gauging_status_locked(void)
{
	u8 data[BQ_RA_GAUGING_DATA_LEN];
	int ret;

	ret = ra_read_client_command_locked(ra_client,
		BQ_RA_CMD_GAUGING_STATUS, data, sizeof(data));
	if (!ret)
		ra_last_gauging_status = ra_status_value(data);
	return ret;
}

static const char *ra_it_status2_lstatus_state(u8 lstatus)
{
	switch (lstatus) {
	case 0x00:
		return "not_learned";
	case 0x04:
	case 0x05:
		return "qmax_updated";
	case 0x0e:
		return "qmax_and_ra_updated";
	default:
		return "other";
	}
}

/* Caller must hold ra_lock. */
static int ra_read_it_status2_locked(void)
{
	u8 data[BQ_RA_IT_STATUS2_DATA_LEN];
	int ret;

	ret = ra_read_client_command_locked(ra_client, BQ_RA_CMD_IT_STATUS2,
		data, sizeof(data));
	if (ret) {
		ra_it_status2_last_error = ret;
		return ret;
	}

	ra_it_status2_pack_grid = data[BQ_RA_IT_STATUS2_PACK_GRID_OFFSET];
	ra_it_status2_lstatus = data[BQ_RA_IT_STATUS2_LSTATUS_OFFSET];
	ra_it_status2_cell_grid1 = data[BQ_RA_IT_STATUS2_CELL_GRID1_OFFSET];
	ra_it_status2_cell_grid2 = data[BQ_RA_IT_STATUS2_CELL_GRID2_OFFSET];
	ra_it_status2_last_error = 0;
	ra_it_status2_timestamp = jiffies;
	ra_it_status2_valid = true;
	return 0;
}
struct ra_it_status1 {
	s16 true_rem_q;
	s16 true_rem_e;
	s16 initial_q;
	s16 initial_e;
	s16 true_full_chg_q;
	s16 true_full_chg_e;
	u16 t_sim;
	u16 t_ambient;
	s16 ra_scale0;
	s16 ra_scale1;
	s16 comp_res1;
	s16 comp_res2;
};

static void ra_parse_it_status1(const u8 *data, struct ra_it_status1 *status)
{
	status->true_rem_q = ra_sle16(data, BQ_RA_IT_TRUE_REM_Q_OFFSET);
	status->true_rem_e = ra_sle16(data, BQ_RA_IT_TRUE_REM_E_OFFSET);
	status->initial_q = ra_sle16(data, BQ_RA_IT_INITIAL_Q_OFFSET);
	status->initial_e = ra_sle16(data, BQ_RA_IT_INITIAL_E_OFFSET);
	status->true_full_chg_q = ra_sle16(data, BQ_RA_IT_TRUE_FULL_CHG_Q_OFFSET);
	status->true_full_chg_e = ra_sle16(data, BQ_RA_IT_TRUE_FULL_CHG_E_OFFSET);
	status->t_sim = ra_le16(data, BQ_RA_IT_T_SIM_OFFSET);
	status->t_ambient = ra_le16(data, BQ_RA_IT_T_AMBIENT_OFFSET);
	status->ra_scale0 = ra_sle16(data, BQ_RA_IT_RA_SCALE0_OFFSET);
	status->ra_scale1 = ra_sle16(data, BQ_RA_IT_RA_SCALE1_OFFSET);
	status->comp_res1 = ra_sle16(data, BQ_RA_IT_COMP_RES1_OFFSET);
	status->comp_res2 = ra_sle16(data, BQ_RA_IT_COMP_RES2_OFFSET);
}

static void ra_poll_workfn(struct work_struct *work)
{
	u8 it_status_data[BQ_RA_IT_STATUS1_DATA_LEN];
	struct ra_it_status1 it_status;
	s16 comp_res1;
	s16 comp_res2;
	s16 scale0_raw;
	s16 scale1_raw;
	u16 scale0;
	u16 scale1;
	s32 cell1_mohm_x10;
	s32 cell2_mohm_x10;
	bool cell1_valid;
	bool cell2_valid;
	bool changed;
	int ret;

	(void)work;
	mutex_lock(&ra_lock);
	if (ra_stopping || !ra_client)
		goto reschedule;

	/* GaugingStatus remains a diagnostic snapshot and is not an event gate. */
	ret = ra_read_gauging_status_locked();
	if (ret)
		pr_err_ratelimited("bq_ra_reader: GaugingStatus poll failed: %d\n",
			ret);

	/* ITStatus2 is diagnostic only; it does not gate CompRes capture. */
	ret = ra_read_it_status2_locked();
	if (ret)
		pr_err_ratelimited("bq_ra_reader: ITStatus2 poll failed: %d\n", ret);

	ret = ra_read_client_command_locked(ra_client, BQ_RA_CMD_IT_STATUS1,
		it_status_data, sizeof(it_status_data));
	if (ret) {
		pr_err_ratelimited("bq_ra_reader: ITStatus1 poll failed: %d\n", ret);
		goto reschedule;
	}

	ra_parse_it_status1(it_status_data, &it_status);
	comp_res1 = it_status.comp_res1;
	comp_res2 = it_status.comp_res2;
	scale0_raw = it_status.ra_scale0;
	scale1_raw = it_status.ra_scale1;
	scale0 = scale0_raw > 0 ? scale0_raw : 0;
	scale1 = scale1_raw > 0 ? scale1_raw : 0;
	if (!ra_it_baseline_valid) {
		ra_it_last_comp_res1 = comp_res1;
		ra_it_last_comp_res2 = comp_res2;
		ra_it_baseline_valid = true;
		goto reschedule;
	}

	changed = comp_res1 != ra_it_last_comp_res1 ||
		comp_res2 != ra_it_last_comp_res2;
	ra_it_last_comp_res1 = comp_res1;
	ra_it_last_comp_res2 = comp_res2;
	if (!changed)
		goto reschedule;

	cell1_valid = ra_comp_res_to_mohm_x10(comp_res1, scale0,
		&cell1_mohm_x10);
	cell2_valid = ra_comp_res_to_mohm_x10(comp_res2, scale1,
		&cell2_mohm_x10);
	ra_comp_res1_raw = comp_res1;
	ra_comp_res2_raw = comp_res2;
	ra_comp_ra_scale0 = scale0;
	ra_comp_ra_scale1 = scale1;
	ra_comp_cell1_valid = cell1_valid;
	ra_comp_cell2_valid = cell2_valid;
	ra_comp_cell1_mohm_x10 = cell1_mohm_x10;
	ra_comp_cell2_mohm_x10 = cell2_mohm_x10;
	ra_comp_timestamp = jiffies;
	ra_comp_capture_count++;
	ra_have_comp_res = true;
	pr_info("bq_ra_reader: ITStatus1 changed comp_res1=%d scale0=%u "
		"comp_res2=%d scale1=%u cell1=%s cell2=%s count=%u\n",
		comp_res1, scale0, comp_res2, scale1,
		cell1_valid ? "valid" : "n/a",
		cell2_valid ? "valid" : "n/a", ra_comp_capture_count);

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

static ssize_t ra_it_status2_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	const char *status;
	const char *lstatus_state;
	int read_error;
	bool valid;
	u8 pack_grid;
	u8 lstatus;
	u8 cell_grid1;
	u8 cell_grid2;
	unsigned long timestamp;

	mutex_lock(&ra_lock);
	if (!ra_client) {
		read_error = -ENODEV;
	} else {
		/* A cat gets a fresh ITStatus2 snapshot, not only the worker cache. */
		read_error = ra_read_it_status2_locked();
	}
	valid = ra_it_status2_valid;
	pack_grid = ra_it_status2_pack_grid;
	lstatus = ra_it_status2_lstatus;
	cell_grid1 = ra_it_status2_cell_grid1;
	cell_grid2 = ra_it_status2_cell_grid2;
	timestamp = ra_it_status2_timestamp;
	if (read_error && !valid)
		status = "error";
	else if (read_error)
		status = "stale";
	else
		status = "valid";
	lstatus_state = ra_it_status2_lstatus_state(lstatus);
	mutex_unlock(&ra_lock);

	if (!valid) {
		return sysfs_emit(buf,
			"status=%s\n"
			"message=ITStatus2 snapshot unavailable\n"
			"command=0x%04x\n"
			"command_echo=74 00\n"
			"read_error=%d\n",
			status, BQ_RA_CMD_IT_STATUS2, read_error);
	}

	return sysfs_emit(buf,
		"status=%s\n"
		"command=0x%04x\n"
		"command_echo=74 00\n"
		"pack_grid=%u\n"
		"pack_grid_response_offset=2\n"
		"lstatus=0x%02x\n"
		"lstatus_response_offset=3\n"
		"lstatus_qmax=%u\n"
		"lstatus_iten=%u\n"
		"lstatus_cf1=%u\n"
		"lstatus_cf0=%u\n"
		"lstatus_state=%s\n"
		"cell_grid1=%u\n"
		"cell_grid1_response_offset=4\n"
		"cell_grid2=%u\n"
		"cell_grid2_response_offset=5\n"
		"raw_payload=%02x %02x %02x %02x\n"
		"capture_timestamp_jiffies=%lu\n"
		"read_error=%d\n",
		status, BQ_RA_CMD_IT_STATUS2,
		pack_grid, lstatus,
		!!(lstatus & IT_STATUS2_LSTATUS_QMAX),
		!!(lstatus & IT_STATUS2_LSTATUS_ITEN),
		!!(lstatus & IT_STATUS2_LSTATUS_CF1),
		!!(lstatus & IT_STATUS2_LSTATUS_CF0),
		lstatus_state, cell_grid1, cell_grid2,
		pack_grid, lstatus, cell_grid1, cell_grid2,
		timestamp, read_error);
}

static int ra_format_mohm(char *buf, size_t size, bool valid, s32 value)
{
	s64 magnitude;

	if (!valid)
		return scnprintf(buf, size, "n/a");
	magnitude = value < 0 ? -(s64)value : value;
	return scnprintf(buf, size, "%s%lld.%lld", value < 0 ? "-" : "",
		magnitude / 10, magnitude % 10);
}

static ssize_t ra_comp_res_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	char cell1_mohm[32];
	char cell2_mohm[32];
	unsigned int interval_ms;
	unsigned int effective_ms;
	bool single_cell_hint;
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
			"last_gauging_status=0x%08x\n"
			"capture_count=0\n",
			interval_ms, effective_ms, ra_last_gauging_status);
	} else {
		ra_format_mohm(cell1_mohm, sizeof(cell1_mohm),
			ra_comp_cell1_valid, ra_comp_cell1_mohm_x10);
		ra_format_mohm(cell2_mohm, sizeof(cell2_mohm),
			ra_comp_cell2_valid, ra_comp_cell2_mohm_x10);
		single_cell_hint = ra_is_single_cell_hint(ra_comp_ra_scale0,
			ra_comp_ra_scale1);
		len = sysfs_emit(buf,
			"status=valid\n"
			"comp_res1_raw=%d\n"
			"comp_res2_raw=%d\n"
			"ra_scale0=%d\n"
			"ra_scale1=%d\n"
			"cell1_mohm=%s\n"
			"cell2_mohm=%s\n"
			"capture_timestamp_jiffies=%lu\n"
			"capture_count=%u\n"
			"cell2_note=%s\n"
			"poll_interval_ms=%u\n"
			"poll_interval_effective_ms=%u\n",
			ra_comp_res1_raw, ra_comp_res2_raw,
			ra_comp_ra_scale0, ra_comp_ra_scale1,
			cell1_mohm, cell2_mohm, ra_comp_timestamp,
			ra_comp_capture_count,
			single_cell_hint ? "Cell2 may be unused on a single-cell design" :
				"Cell2 scale is not in the single-cell hint range",
			interval_ms, effective_ms);
	}
	mutex_unlock(&ra_lock);
	return len;
}

static struct kobj_attribute ra_table_attr = __ATTR_RO(ra_table);
static struct kobj_attribute ra_comp_res_attr =
	__ATTR(comp_res, 0444, ra_comp_res_show, NULL);
static struct kobj_attribute ra_it_status2_attr =
	__ATTR(it_status2, 0444, ra_it_status2_show, NULL);

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
	ret = ra_read_gauging_status_locked();
	if (ret)
		pr_warn("bq_ra_reader: initial GaugingStatus read failed: %d; "
			"polling will retry the diagnostic snapshot\n", ret);
	ret = ra_read_it_status2_locked();
	mutex_unlock(&ra_lock);
	if (ret)
		pr_warn("bq_ra_reader: initial ITStatus2 read failed: %d; "
			"sysfs and polling will retry it\n", ret);

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

	ret = sysfs_create_file(ra_kobj, &ra_it_status2_attr.attr);
	if (ret)
		goto remove_comp_res;

	pr_info("bq_ra_reader: ready for %s-%04x, poll_interval=%ums\n",
		dev_name(&ra_client->adapter->dev), ra_client->addr,
		ra_effective_poll_interval_ms());
	schedule_delayed_work(&ra_poll_work, ra_poll_delay());
	return 0;

remove_comp_res:
	sysfs_remove_file(ra_kobj, &ra_comp_res_attr.attr);
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
		sysfs_remove_file(ra_kobj, &ra_it_status2_attr.attr);
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

MODULE_DESCRIPTION("BQ28Z610 ITStatus1 CompRes change probe");
MODULE_LICENSE("GPL v2");
