// SPDX-License-Identifier: GPL-2.0
/*
 * Reusable I2C MAC (AltManufacturerAccess) read framework.
 *
 * A BQ28Z610-compatible diagnostic loader. Writing a 16-bit MAC subcommand or
 * Data Flash address to AltManufacturerAccess (0x3E lo / 0x3F hi) makes the
 * gauge fill the 36-byte window 0x3E..0x61; the raw window is always reported,
 * even when validation fails, so a failing Data Flash read stays diagnosable.
 * It also exposes sealed/seal nodes for type4 gauges; every security-changing
 * operation re-identifies the live gauge first.
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
/*
 * 写 0x3E/0x3F 之后、读窗口之前的整定时间。原 gauge 驱动的
 * fg_mac_read_block() 用 udelay(4000)，约 4ms；可用 settle_ms 节点在不
 * 重新编译的情况下调整，用来判断 DF 块是否比 MAC 块需要更长整定。
 */
#define RA_SETTLE_MS_DEFAULT		4
#define RA_SETTLE_MS_MAX		5000

/* ra_result_reason 取值（诊断用，校验失败也要说清原因）。 */
#define RA_REASON_OK			0
#define RA_REASON_LENGTH		1
#define RA_REASON_CKSUM			2
#define RA_REASON_EMPTY			3
#define RA_REASON_IO			4
#define RA_REASON_STALE			5

/* 0x0054 payload byte 1 & 0x03：TI gauge 的安全等级。 */
#define RA_SECURITY_FULL_ACCESS		0x01
#define RA_SECURITY_UNSEALED		0x02
#define RA_SECURITY_SEALED		0x03
#define RA_FORCE_UNSEAL_MAX		5

/* regs 节点转储的寄存器范围（用于确认 DF 数据是否落在别的窗口）。 */
#define RA_REG_DUMP_FIRST		0x00
#define RA_REG_DUMP_LAST		0x7f
#define RA_REG_DUMP_LEN			(RA_REG_DUMP_LAST - RA_REG_DUMP_FIRST + 1)

/* RA 表所在的四个 32 字节 DF 块（Cell0/Cell1 及其影子表）。 */
#define RA_DF_CELL0_RA			0x4100
#define RA_DF_CELL1_RA			0x4140
#define RA_DF_XCELL0_RA			0x4180
#define RA_DF_XCELL1_RA			0x41c0
#define RA_TABLE_POINTS			15

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

/* 以下字段均由 ra_lock 保护。 */
static bool ra_stopping;
static u16 ra_cmd;
static bool ra_result_valid;
static int ra_result_error;
static u8 ra_result_raw[RA_READ_LEN];
static unsigned long ra_result_timestamp;
static int ra_result_reason;
static unsigned int ra_settle_ms = RA_SETTLE_MS_DEFAULT;

static const char *ra_reason_name(int reason);

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
 * Read one MAC command / Data Flash address. Caller must hold ra_lock.
 *
 * Writes the 16-bit command word to AltManufacturerAccess (0x3E lo / 0x3F hi),
 * waits ra_settle_ms, then reads the fixed 36-byte window 0x3E..0x61:
 *   [0..1]   0x3E/0x3F command echo
 *   [2..33]  0x40..0x5F payload
 *   [34]     0x60 checksum
 *   [35]     0x61 length
 *
 * The raw window is handed back to the caller even when validation fails, so a
 * failing Data Flash read can still be diagnosed from sysfs.
 */
static int ra_read_mac_block(const struct i2c_client *client, u16 cmd,
			     u8 *raw_response, int *reason)
{
	u8 response[RA_READ_LEN];
	u8 before[RA_READ_LEN];
	u8 value;
	u8 length;
	unsigned int settle_ms;
	int reason_local;
	int ret;
	int i;

	if (!raw_response)
		return -EINVAL;

	/* reason 只是诊断出口，调用方（type4 识别等）可以传 NULL。 */
	if (!reason)
		reason = &reason_local;

	*reason = RA_REASON_OK;

	/*
	 * 先记下命令之前的窗口。gauge 忽略某个命令时，只有 0x3E/0x3F 会被我们
	 * 的写改掉，其余字节与命令前完全相同；这样从第一条命令起就能把"没响应"
	 * 和"响应了但校验不过"区分开，而不是等到第二条才有 prev 可比。
	 */
	for (i = 0; i < RA_READ_LEN; i++) {
		ret = ra_smbus_byte_data(client, true, RA_REG_ALT_MAC + i,
			&before[i]);
		if (ret) {
			*reason = RA_REASON_IO;
			return ret;
		}
	}

	value = cmd & 0xff;
	ret = ra_smbus_byte_data(client, false, RA_REG_ALT_MAC, &value);
	if (ret) {
		*reason = RA_REASON_IO;
		return ret;
	}
	value = cmd >> 8;
	ret = ra_smbus_byte_data(client, false, RA_REG_ALT_MAC + 1, &value);
	if (ret) {
		*reason = RA_REASON_IO;
		return ret;
	}

	/* 与原 gauge 的 fg_mac_read_block() 一致：写地址后先整定再读窗口。 */
	settle_ms = ra_settle_ms;
	if (settle_ms)
		msleep(settle_ms);

	/* Read each register separately, matching fg_read_block(). */
	for (i = 0; i < RA_READ_LEN; i++) {
		ret = ra_smbus_byte_data(client, true, RA_REG_ALT_MAC + i,
			&response[i]);
		if (ret) {
			*reason = RA_REASON_IO;
			return ret;
		}
	}

	/* 先留证据：任何校验分支都不再吞掉窗口内容。 */
	memcpy(raw_response, response, RA_READ_LEN);

	length = response[RA_READ_LEN - 1];
	if (length == 2) {
		/* fg_mac_read_block() 把 length==2 当合法空块，校验固定 0xFF。 */
		if (response[RA_READ_LEN - 2] != 0xff) {
			*reason = RA_REASON_CKSUM;
			return -EBADMSG;
		}
		*reason = RA_REASON_EMPTY;
		return 0;
	}

	if (length < 3 || length > RA_READ_LEN) {
		pr_err_ratelimited("raR: bad MAC response cmd=0x%04x len=%u\n",
			cmd, length);
		*reason = RA_REASON_LENGTH;
		return -EBADMSG;
	}

	/* 读路径约定：校验和覆盖 length-2 字节（见 fg_mac_read_block）。 */
	if (ra_checksum(response, length - 2) != response[RA_READ_LEN - 2]) {
		if (!memcmp(&response[2], &before[2], RA_READ_LEN - 2))
			*reason = RA_REASON_STALE;
		else
			*reason = RA_REASON_CKSUM;

		pr_err_ratelimited("raR: MAC checksum mismatch cmd=0x%04x len=%u (%s)\n",
			cmd, length, ra_reason_name(*reason));
		return -EBADMSG;
	}

	return 0;
}

/* Caller must hold ra_lock. */
static int ra_read_client_command_locked(struct i2c_client *client, u16 cmd,
					 u8 *raw_response, int *reason)
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
	ret = ra_read_mac_block(client, cmd, raw_response, reason);
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

	ret = ra_read_client_command_locked(client, RA_CMD_DEVICE_NAME, raw,
		NULL);
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

	ret = ra_read_client_command_locked(client, RA_CMD_OPERATION_STATUS,
		raw, NULL);
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
 * type4 有两套 key：普通 SKU 用 0x645923cf，xagapro 用 0x5502020b。
 * 内核侧无法读取 hwid 的 SKU：引用弱符号会产生 5.10 加载器不支持的
 * GOT 重定位（insmod 报 unsupported RELA relocation 312），因此每个
 * 重试周期交替尝试两套 key；写错 key 无害，gauge 只是拒绝解锁。
 */
static const u32 ra_unseal_keys[] = {
	RA_UNSEAL_KEY,
	RA_UNSEAL_KEY_XAGAPRO,
};

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

	for (attempt = 0; attempt < RA_UNSEAL_RETRIES; attempt++) {
		/* Re-check immediately before every security-changing transaction. */
		ret = ra_check_type4_locked(client);
		if (ret)
			break;

		if (want_sealed)
			ret = ra_write_word_locked(client, RA_REG_ALT_MAC,
						  RA_CMD_SEAL);
		else
			ret = ra_send_unseal_key_locked(client,
				ra_unseal_keys[attempt % ARRAY_SIZE(ra_unseal_keys)]);
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

/*
 * 写地址与读窗口本来就是原子的，排一个延迟工作没有意义；同步执行之后
 * 一个 shell 循环就能扫完整片子命令/地址空间（每次约 10ms）。
 */
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
	ra_result_reason = RA_REASON_OK;
	ret = ra_read_client_command_locked(ra_client, cmd, ra_result_raw,
		&ra_result_reason);
	ra_result_error = ret;
	ra_result_valid = true;
	ra_result_timestamp = jiffies;
	mutex_unlock(&ra_lock);

	return count;
}

static const char *ra_reason_name(int reason)
{
	switch (reason) {
	case RA_REASON_OK:
		return "ok";
	case RA_REASON_LENGTH:
		return "bad-length";
	case RA_REASON_CKSUM:
		return "checksum-mismatch";
	case RA_REASON_EMPTY:
		return "empty-block";
	case RA_REASON_IO:
		return "i2c-error";
	case RA_REASON_STALE:
		return "stale-window";
	default:
		return "unknown";
	}
}

/* DF map 里的 RA 表块：2 字节 flag + 15 个 I2（单位 2^-10 欧）。 */
static bool ra_is_ra_block(u16 cmd)
{
	return cmd == RA_DF_CELL0_RA || cmd == RA_DF_CELL1_RA ||
		cmd == RA_DF_XCELL0_RA || cmd == RA_DF_XCELL1_RA;
}

/*
 * 按小端解释 RA 值。默认 flag 是 0xFF55，若打印出来的高低字节相反，
 * 说明该字段用另一套字节序，以 raw_response 那一行为准。
 */
static void ra_emit_ra_table(char *buf, ssize_t *len, const u8 *raw)
{
	unsigned int flag = raw[2] | (raw[3] << 8);
	int i;

	*len += sysfs_emit_at(buf, *len, "ra_flag=0x%04x\n", flag);
	for (i = 0; i < RA_TABLE_POINTS; i++) {
		s16 value = (s16)(raw[4 + 2 * i] | (raw[5 + 2 * i] << 8));

		*len += sysfs_emit_at(buf, *len, "ra[%02d]=%d (%d mOhm)\n",
			i, value, value * 1000 / 1024);
	}
}

static ssize_t ra_show_result(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	u8 raw[RA_READ_LEN];
	ssize_t len;
	bool valid;
	u16 cmd;
	int error;
	int reason;
	unsigned long timestamp;
	unsigned int settle_ms;
	u8 length;
	int i;

	mutex_lock(&ra_lock);
	valid = ra_result_valid;
	cmd = ra_cmd;
	error = ra_result_error;
	reason = ra_result_reason;
	timestamp = ra_result_timestamp;
	settle_ms = ra_settle_ms;
	memcpy(raw, ra_result_raw, RA_READ_LEN);
	mutex_unlock(&ra_lock);

	if (!valid)
		return sysfs_emit(buf, "status=pending\ncommand=0x%04x\n", cmd);

	if (error)
		len = sysfs_emit(buf, "status=error\n");
	else if (reason == RA_REASON_EMPTY)
		len = sysfs_emit(buf, "status=empty\n");
	else
		len = sysfs_emit(buf, "status=done\n");

	len += sysfs_emit_at(buf, len, "command=0x%04x\n", cmd);
	if (error)
		len += sysfs_emit_at(buf, len, "read_error=%d\n", error);
	len += sysfs_emit_at(buf, len, "reason=%s\n", ra_reason_name(reason));
	len += sysfs_emit_at(buf, len, "settle_ms=%u\n", settle_ms);

	/* 校验通过与否都打印窗口：这是定位 DF 读取失败的唯一证据。 */
	len += sysfs_emit_at(buf, len, "raw_response[0..35]=");
	for (i = 0; i < RA_READ_LEN; i++)
		len += sysfs_emit_at(buf, len, "%s%02x", i ? " " : "", raw[i]);
	len += sysfs_emit_at(buf, len, "\n");

	len += sysfs_emit_at(buf, len,
		"command_echo=%02x %02x (expected %02x %02x, %s)\n",
		raw[0], raw[1], cmd & 0xff, cmd >> 8,
		(raw[0] == (cmd & 0xff) && raw[1] == (cmd >> 8)) ?
			"match" : "MISMATCH");
	len += sysfs_emit_at(buf, len, "response_checksum_byte=%02x\n",
		raw[RA_READ_LEN - 2]);
	len += sysfs_emit_at(buf, len, "response_length_byte=%u\n",
		raw[RA_READ_LEN - 1]);

	/*
	 * 满 32 字节 payload（length==36）时给一份 u16 小端视图：找 Ra Table
	 * 这类"连续多个 I2"的数据块时，一眼就能看出形态，不用另外解码。
	 */
	if (length == RA_READ_LEN) {
		len += sysfs_emit_at(buf, len, "payload_u16[0..15]=");
		for (i = 0; i < (RA_READ_LEN - 4) / 2; i++) {
			s16 value = (s16)(raw[2 + 2 * i] |
				(raw[3 + 2 * i] << 8));

			len += sysfs_emit_at(buf, len, "%s%d", i ? " " : "",
				value);
		}
		len += sysfs_emit_at(buf, len, "\n");
	}

	/*
	 * 原驱动两条路径的校验约定相差 2 字节，两个都算出来对比：
	 *   读校验 fg_mac_read_block  -> 覆盖 length-2 字节
	 *   写构造 fg_mac_write_block -> 覆盖 length 字节
	 */
	length = raw[RA_READ_LEN - 1];
	if (length >= 3 && length <= RA_READ_LEN) {
		len += sysfs_emit_at(buf, len,
			"checksum_readpath=%02x (sum of first %u bytes)\n",
			ra_checksum(raw, length - 2), length - 2);
		len += sysfs_emit_at(buf, len,
			"checksum_writepath=%02x (sum of first %u bytes)\n",
			ra_checksum(raw, length), length);
	}

	if (!error && length >= 4 + 2 * RA_TABLE_POINTS && ra_is_ra_block(cmd))
		ra_emit_ra_table(buf, &len, raw);

	len += sysfs_emit_at(buf, len, "timestamp_jiffies=%lu\n", timestamp);

	return len;
}

static struct kobj_attribute ra_store_attr =
	__ATTR(mac_cmd, 0200, NULL, ra_store_cmd);
static struct kobj_attribute ra_result_attr =
	__ATTR(mac_result, 0444, ra_show_result, NULL);

static ssize_t ra_show_settle(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", ra_settle_ms);
}

static ssize_t ra_store_settle(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	unsigned int value;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = kstrtouint(buf, 0, &value);
	if (ret || value > RA_SETTLE_MS_MAX)
		return -EINVAL;

	mutex_lock(&ra_lock);
	ra_settle_ms = value;
	mutex_unlock(&ra_lock);

	return count;
}

static struct kobj_attribute ra_settle_attr =
	__ATTR(settle_ms, 0600, ra_show_settle, ra_store_settle);

static const char *ra_security_name(u8 mode)
{
	switch (mode) {
	case RA_SECURITY_FULL_ACCESS:
		return "FULL-ACCESS";
	case RA_SECURITY_UNSEALED:
		return "UNSEALED";
	case RA_SECURITY_SEALED:
		return "SEALED";
	default:
		return "unknown";
	}
}

/* Caller must hold ra_lock. 读 0x0054 的 payload byte 1（安全等级）。 */
static int ra_read_security_locked(struct i2c_client *client, u8 *mode)
{
	u8 raw[RA_READ_LEN];
	int ret;

	ret = ra_read_client_command_locked(client, RA_CMD_OPERATION_STATUS,
		raw, NULL);
	if (ret)
		return ret;

	if (raw[0] != (RA_CMD_OPERATION_STATUS & 0xff) ||
		raw[1] != (RA_CMD_OPERATION_STATUS >> 8) ||
		raw[RA_READ_LEN - 1] < RA_STATUS_DATA_LEN + 4)
		return -EBADMSG;

	*mode = raw[3] & 0x03;
	return 0;
}

static ssize_t ra_show_security(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	u8 mode = 0;
	int ret;

	mutex_lock(&ra_lock);
	if (ra_stopping || !ra_client) {
		ret = -ENODEV;
	} else {
		ret = ra_check_type4_locked(ra_client);
		if (!ret)
			ret = ra_read_security_locked(ra_client, &mode);
	}
	mutex_unlock(&ra_lock);

	if (ret)
		return ret;

	return sysfs_emit(buf, "mode=%u (%s)\n", mode, ra_security_name(mode));
}

/*
 * TI gauge 的 FULL ACCESS 通常要在已经 UNSEALED 的状态下再输一遍 key 才能
 * 到达，而 sealed 节点在"已经是未封存"时会短路、不再发 key。这里给一个强制
 * 入口：写 N 就发 N 轮 unseal key（两套候选 key 交替），随后用 security 节点
 * 看是否升到了 FULL-ACCESS(1)。
 */
static ssize_t ra_store_force_unseal(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	static unsigned int round;
	unsigned int times;
	unsigned int i;
	u8 mode = 0;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = kstrtouint(buf, 0, &times);
	if (ret || times < 1 || times > RA_FORCE_UNSEAL_MAX)
		return -EINVAL;

	mutex_lock(&ra_lock);
	if (ra_stopping || !ra_client) {
		ret = -ENODEV;
		goto out;
	}

	ret = ra_check_type4_locked(ra_client);
	if (ret)
		goto out;

	for (i = 0; i < times; i++) {
		ret = ra_send_unseal_key_locked(ra_client,
			ra_unseal_keys[round++ % ARRAY_SIZE(ra_unseal_keys)]);
		if (ret)
			break;
		msleep(RA_SECURITY_POLL_DELAY_MS);
	}
	if (!ret)
		ret = ra_read_security_locked(ra_client, &mode);

out:
	mutex_unlock(&ra_lock);
	if (ret)
		return ret;

	pr_info("raR: force unseal x%u -> security mode %u (%s)\n", times, mode,
		ra_security_name(mode));
	return count;
}

/*
 * 把 0x00..0x7F 整个寄存器窗口转储出来，用于确认 DF 数据是不是落在
 * 0x40..0x5F 之外的窗口（若某条 DF 命令后别处出现新数据，路径就找到了）。
 */
static ssize_t ra_show_regs(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	u8 value;
	ssize_t len = 0;
	int ret = 0;
	int i;

	mutex_lock(&ra_lock);
	if (ra_stopping || !ra_client) {
		ret = -ENODEV;
		goto out;
	}

	device_lock(&ra_client->dev);
	if (!ra_client->dev.driver ||
		strcmp(ra_client->dev.driver->name, RA_DRIVER_NAME)) {
		device_unlock(&ra_client->dev);
		ret = -ENODEV;
		goto out;
	}

	i2c_lock_bus(ra_client->adapter, I2C_LOCK_SEGMENT);
	for (i = 0; i < RA_REG_DUMP_LEN; i++) {
		ret = ra_smbus_byte_data(ra_client, true,
			RA_REG_DUMP_FIRST + i, &value);
		if (ret)
			break;
		len += sysfs_emit_at(buf, len, "%02x:%02x ",
			RA_REG_DUMP_FIRST + i, value);
	}
	i2c_unlock_bus(ra_client->adapter, I2C_LOCK_SEGMENT);
	device_unlock(&ra_client->dev);

out:
	mutex_unlock(&ra_lock);
	if (ret < 0)
		return ret;

	len += sysfs_emit_at(buf, len, "\n");
	return len;
}

static struct kobj_attribute ra_security_attr =
	__ATTR(security, 0444, ra_show_security, NULL);
static struct kobj_attribute ra_force_unseal_attr =
	__ATTR(force_unseal, 0200, NULL, ra_store_force_unseal);
static struct kobj_attribute ra_regs_attr =
	__ATTR(regs, 0444, ra_show_regs, NULL);

static int __init ra_init(void)
{
	struct ra_find_context context = {};
	int ret;

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

	ret = sysfs_create_file(ra_kobj, &ra_settle_attr.attr);
	if (ret)
		goto remove_seal;

	ret = sysfs_create_file(ra_kobj, &ra_security_attr.attr);
	if (ret)
		goto remove_settle;

	ret = sysfs_create_file(ra_kobj, &ra_force_unseal_attr.attr);
	if (ret)
		goto remove_security;

	ret = sysfs_create_file(ra_kobj, &ra_regs_attr.attr);
	if (ret)
		goto remove_force_unseal;

	pr_info("raR: ready for %s-%04x, sync read, settle=%ums, type4 security nodes enabled\n",
		dev_name(&ra_client->adapter->dev), ra_client->addr,
		ra_settle_ms);
	return 0;

remove_force_unseal:
	sysfs_remove_file(ra_kobj, &ra_force_unseal_attr.attr);
remove_security:
	sysfs_remove_file(ra_kobj, &ra_security_attr.attr);
remove_settle:
	sysfs_remove_file(ra_kobj, &ra_settle_attr.attr);
remove_seal:
	sysfs_remove_file(ra_kobj, &ra_seal_attr.attr);
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

	if (ra_kobj) {
		sysfs_remove_file(ra_kobj, &ra_seal_attr.attr);
		sysfs_remove_file(ra_kobj, &ra_settle_attr.attr);
		sysfs_remove_file(ra_kobj, &ra_regs_attr.attr);
		sysfs_remove_file(ra_kobj, &ra_force_unseal_attr.attr);
		sysfs_remove_file(ra_kobj, &ra_security_attr.attr);
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
