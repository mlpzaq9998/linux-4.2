/*
 * Copyright 2015 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: AMD
 *
 */

#include <linux/string.h>
#include <linux/acpi.h>
#include <linux/version.h>
#include <linux/i2c.h>

#include <drm/drmP.h>
#include <drm/drm_crtc_helper.h>
#include <drm/amdgpu_drm.h>
#include <drm/drm_edid.h>

#include "dm_services.h"
#include "amdgpu.h"
#include "dc.h"
#include "amdgpu_dm.h"
#include "amdgpu_dm_irq.h"
#include "amdgpu_dm_types.h"

#include "dm_helpers.h"

/* Maximum line char number for connectivity log,
 * in case of output EDID, needs at least 256x3 bytes plus some other
 * message, so set line size to 896.
 */
#define CONN_MAX_LINE_SIZE 896

/* dm_helpers_parse_edid_caps
 *
 * Parse edid caps
 *
 * @edid:	[in] pointer to edid
 *  edid_caps:	[in] pointer to edid caps
 * @return
 *	void
 * */
enum dc_edid_status dm_helpers_parse_edid_caps(
		struct dc_context *ctx,
		const struct dc_edid *edid,
		struct dc_edid_caps *edid_caps)
{
	struct edid *edid_buf = (struct edid *) edid->raw_edid;
	struct cea_sad *sads;
	int sad_count = -1;
	int sadb_count = -1;
	int i = 0;
	int j = 0;
	uint8_t *sadb = NULL;

	enum dc_edid_status result = EDID_OK;

	if (!edid_caps || !edid)
		return EDID_BAD_INPUT;

	if (!drm_edid_is_valid(edid_buf))
		result = EDID_BAD_CHECKSUM;

	edid_caps->manufacturer_id = (uint16_t) edid_buf->mfg_id[0] |
					((uint16_t) edid_buf->mfg_id[1])<<8;
	edid_caps->product_id = (uint16_t) edid_buf->prod_code[0] |
					((uint16_t) edid_buf->prod_code[1])<<8;
	edid_caps->serial_number = edid_buf->serial;
	edid_caps->manufacture_week = edid_buf->mfg_week;
	edid_caps->manufacture_year = edid_buf->mfg_year;

	/* One of the four detailed_timings stores the monitor name. It's
	 * stored in an array of length 13. */
	for (i = 0; i < 4; i++) {
		if (edid_buf->detailed_timings[i].data.other_data.type == 0xfc) {
			while (edid_buf->detailed_timings[i].data.other_data.data.str.str[j] && j < 13) {
				if (edid_buf->detailed_timings[i].data.other_data.data.str.str[j] == '\n')
					break;

				edid_caps->display_name[j] =
					edid_buf->detailed_timings[i].data.other_data.data.str.str[j];
				j++;
			}
		}
	}

	sad_count = drm_edid_to_sad((struct edid *) edid->raw_edid, &sads);
	if (sad_count <= 0) {
		DRM_INFO("SADs count is: %d, don't need to read it\n",
				sad_count);
		return result;
	}

	edid_caps->audio_mode_count = sad_count < DC_MAX_AUDIO_DESC_COUNT ? sad_count : DC_MAX_AUDIO_DESC_COUNT;
	for (i = 0; i < edid_caps->audio_mode_count; ++i) {
		struct cea_sad *sad = &sads[i];

		edid_caps->audio_modes[i].format_code = sad->format;
		edid_caps->audio_modes[i].channel_count = sad->channels;
		edid_caps->audio_modes[i].sample_rate = sad->freq;
		edid_caps->audio_modes[i].sample_size = sad->byte2;
	}

	sadb_count = drm_edid_to_speaker_allocation((struct edid *) edid->raw_edid, &sadb);

	if (sadb_count < 0) {
		DRM_ERROR("Couldn't read Speaker Allocation Data Block: %d\n", sadb_count);
		sadb_count = 0;
	}

	if (sadb_count)
		edid_caps->speaker_flags = sadb[0];
	else
		edid_caps->speaker_flags = DEFAULT_SPEAKER_LOCATION;

	kfree(sads);
	kfree(sadb);

	return result;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
static struct amdgpu_connector *get_connector_for_sink(
	struct drm_device *dev,
	const struct dc_sink *sink)
{
	struct drm_connector *connector;
	struct amdgpu_connector *aconnector = NULL;

	list_for_each_entry(connector, &dev->mode_config.connector_list, head) {
		aconnector = to_amdgpu_connector(connector);
		if (aconnector->dc_sink == sink)
			break;
	}

	return aconnector;
}
#endif

static struct amdgpu_connector *get_connector_for_link(
	struct drm_device *dev,
	const struct dc_link *link)
{
	struct drm_connector *connector;
	struct amdgpu_connector *aconnector = NULL;

	list_for_each_entry(connector, &dev->mode_config.connector_list, head) {
		aconnector = to_amdgpu_connector(connector);
		if (aconnector->dc_link == link)
			break;
	}

	return aconnector;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
static void get_payload_table(
		struct amdgpu_connector *aconnector,
		struct dp_mst_stream_allocation_table *proposed_table)
{
	int i;
	struct drm_dp_mst_topology_mgr *mst_mgr =
			&aconnector->mst_port->mst_mgr;

	mutex_lock(&mst_mgr->payload_lock);

	proposed_table->stream_count = 0;

	/* number of active streams */
	for (i = 0; i < mst_mgr->max_payloads; i++) {
		if (mst_mgr->payloads[i].num_slots == 0)
			break; /* end of vcp_id table */

		ASSERT(mst_mgr->payloads[i].payload_state !=
				DP_PAYLOAD_DELETE_LOCAL);

		if (mst_mgr->payloads[i].payload_state == DP_PAYLOAD_LOCAL ||
			mst_mgr->payloads[i].payload_state ==
					DP_PAYLOAD_REMOTE) {

			struct dp_mst_stream_allocation *sa =
					&proposed_table->stream_allocations[
						proposed_table->stream_count];

			sa->slot_count = mst_mgr->payloads[i].num_slots;
			sa->vcp_id = mst_mgr->proposed_vcpis[i]->vcpi;
			proposed_table->stream_count++;
		}
	}

	mutex_unlock(&mst_mgr->payload_lock);
}
#endif

/*
 * Writes payload allocation table in immediate downstream device.
 */
bool dm_helpers_dp_mst_write_payload_allocation_table(
		struct dc_context *ctx,
		const struct dc_stream *stream,
		struct dp_mst_stream_allocation_table *proposed_table,
		bool enable)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	struct amdgpu_device *adev = ctx->driver_context;
	struct drm_device *dev = adev->ddev;
	struct amdgpu_connector *aconnector;
	struct drm_dp_mst_topology_mgr *mst_mgr;
	struct drm_dp_mst_port *mst_port;
	int slots = 0;
	bool ret;
	int clock;
	int bpp = 0;
	int pbn = 0;

	aconnector = get_connector_for_sink(dev, stream->sink);

	if (!aconnector->mst_port)
		return false;

	mst_mgr = &aconnector->mst_port->mst_mgr;

	if (!mst_mgr->mst_state)
		return false;

	mst_port = aconnector->port;

	if (enable) {
		clock = stream->timing.pix_clk_khz;

		switch (stream->timing.display_color_depth) {

		case COLOR_DEPTH_666:
			bpp = 6;
			break;
		case COLOR_DEPTH_888:
			bpp = 8;
			break;
		case COLOR_DEPTH_101010:
			bpp = 10;
			break;
		case COLOR_DEPTH_121212:
			bpp = 12;
			break;
		case COLOR_DEPTH_141414:
			bpp = 14;
			break;
		case COLOR_DEPTH_161616:
			bpp = 16;
			break;
		default:
			ASSERT(bpp != 0);
			break;
		}

		bpp = bpp * 3;

		/* TODO need to know link rate */

		pbn = drm_dp_calc_pbn_mode(clock, bpp);

		ret = drm_dp_mst_allocate_vcpi(mst_mgr, mst_port, pbn, &slots);

		if (!ret)
			return false;

	} else {
		drm_dp_mst_reset_vcpi_slots(mst_mgr, mst_port);
	}

	ret = drm_dp_update_payload_part1(mst_mgr);

	/* mst_mgr->->payloads are VC payload notify MST branch using DPCD or
	 * AUX message. The sequence is slot 1-63 allocated sequence for each
	 * stream. AMD ASIC stream slot allocation should follow the same
	 * sequence. copy DRM MST allocation to dc */

	get_payload_table(aconnector, proposed_table);

	if (ret)
		return false;

	return true;
#else
	return false;
#endif
}

/*
 * Polls for ACT (allocation change trigger) handled and sends
 * ALLOCATE_PAYLOAD message.
 */
bool dm_helpers_dp_mst_poll_for_allocation_change_trigger(
		struct dc_context *ctx,
		const struct dc_stream *stream)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	struct amdgpu_device *adev = ctx->driver_context;
	struct drm_device *dev = adev->ddev;
	struct amdgpu_connector *aconnector;
	struct drm_dp_mst_topology_mgr *mst_mgr;
	int ret;

	aconnector = get_connector_for_sink(dev, stream->sink);

	if (!aconnector->mst_port)
		return false;

	mst_mgr = &aconnector->mst_port->mst_mgr;

	if (!mst_mgr->mst_state)
		return false;

	ret = drm_dp_check_act_status(mst_mgr);

	if (ret)
		return false;

	return true;
#else
	return false;
#endif
}

bool dm_helpers_dp_mst_send_payload_allocation(
		struct dc_context *ctx,
		const struct dc_stream *stream,
		bool enable)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	struct amdgpu_device *adev = ctx->driver_context;
	struct drm_device *dev = adev->ddev;
	struct amdgpu_connector *aconnector;
	struct drm_dp_mst_topology_mgr *mst_mgr;
	struct drm_dp_mst_port *mst_port;
	int ret;

	aconnector = get_connector_for_sink(dev, stream->sink);

	mst_port = aconnector->port;

	if (!aconnector->mst_port)
		return false;

	mst_mgr = &aconnector->mst_port->mst_mgr;

	if (!mst_mgr->mst_state)
		return false;

	ret = drm_dp_update_payload_part2(mst_mgr);

	if (ret)
		return false;

	if (!enable)
		drm_dp_mst_deallocate_vcpi(mst_mgr, mst_port);

	return true;
#else
	return false;
#endif
}

void dm_helpers_dp_mst_handle_mst_hpd_rx_irq(void *param)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	uint8_t esi[8] = { 0 };
	uint8_t dret;
	bool new_irq_handled = true;
	struct amdgpu_connector *aconnector = (struct amdgpu_connector *)param;

	/* DPCD 0x2002 - 0x2008 for down stream IRQ from MST, eDP etc. */
	dret = drm_dp_dpcd_read(
		&aconnector->dm_dp_aux.aux,
		DP_SINK_COUNT_ESI, esi, 8);

	while ((dret == 8) && new_irq_handled) {
		uint8_t retry;

		DRM_DEBUG_KMS("ESI %02x %02x %02x\n", esi[0], esi[1], esi[2]);

		/* handle HPD short pulse irq */
		drm_dp_mst_hpd_irq(&aconnector->mst_mgr, esi, &new_irq_handled);

		if (new_irq_handled) {
			/* ACK at DPCD to notify down stream */
			for (retry = 0; retry < 3; retry++) {
				uint8_t wret;

				wret = drm_dp_dpcd_write(
					&aconnector->dm_dp_aux.aux,
					DP_SINK_COUNT_ESI + 1,
					&esi[1],
					3);
				if (wret == 3)
					break;
			}

			/* check if there is new irq to be handle */
			dret = drm_dp_dpcd_read(
				&aconnector->dm_dp_aux.aux,
				DP_SINK_COUNT_ESI, esi, 8);
		}
	}
#else
	return ;
#endif
}

bool dm_helpers_dp_mst_start_top_mgr(
		struct dc_context *ctx,
		const struct dc_link *link,
		bool boot)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	struct amdgpu_device *adev = ctx->driver_context;
	struct drm_device *dev = adev->ddev;
	struct amdgpu_connector *aconnector = get_connector_for_link(dev, link);

	if (boot) {
		DRM_INFO("DM_MST: Differing MST start on aconnector: %p [id: %d]\n",
					aconnector, aconnector->base.base.id);
		return true;
	}

	DRM_INFO("DM_MST: starting TM on aconnector: %p [id: %d]\n",
			aconnector, aconnector->base.base.id);

	return (drm_dp_mst_topology_mgr_set_mst(&aconnector->mst_mgr, true) == 0);
#else
	return false;
#endif
}

void dm_helpers_dp_mst_stop_top_mgr(
		struct dc_context *ctx,
		const struct dc_link *link)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	struct amdgpu_device *adev = ctx->driver_context;
	struct drm_device *dev = adev->ddev;
	struct amdgpu_connector *aconnector = get_connector_for_link(dev, link);

	DRM_INFO("DM_MST: stopping TM on aconnector: %p [id: %d]\n",
			aconnector, aconnector->base.base.id);

	if (aconnector->mst_mgr.mst_state == true)
		drm_dp_mst_topology_mgr_set_mst(&aconnector->mst_mgr, false);
#endif
}

bool dm_helpers_dp_read_dpcd(
		struct dc_context *ctx,
		const struct dc_link *link,
		uint32_t address,
		uint8_t *data,
		uint32_t size)
{

	struct amdgpu_device *adev = ctx->driver_context;
	struct drm_device *dev = adev->ddev;
	struct amdgpu_connector *aconnector = get_connector_for_link(dev, link);

	if (!aconnector) {
		DRM_ERROR("Failed to found connector for link!");
		return false;
	}

	return drm_dp_dpcd_read(&aconnector->dm_dp_aux.aux, address,
			data, size) > 0;
}

bool dm_helpers_dp_write_dpcd(
		struct dc_context *ctx,
		const struct dc_link *link,
		uint32_t address,
		const uint8_t *data,
		uint32_t size)
{

	struct amdgpu_device *adev = ctx->driver_context;
	struct drm_device *dev = adev->ddev;
	struct amdgpu_connector *aconnector = get_connector_for_link(dev, link);

	if (!aconnector) {
		DRM_ERROR("Failed to found connector for link!");
		return false;
	}

	return drm_dp_dpcd_write(&aconnector->dm_dp_aux.aux,
			address, (uint8_t *)data, size) > 0;
}

bool dm_helpers_submit_i2c(
		struct dc_context *ctx,
		const struct dc_link *link,
		struct i2c_command *cmd)
{
	struct amdgpu_device *adev = ctx->driver_context;
	struct drm_device *dev = adev->ddev;
	struct amdgpu_connector *aconnector = get_connector_for_link(dev, link);
	struct i2c_msg *msgs;
	int i = 0;
	int num = cmd->number_of_payloads;
	bool result;

	if (!aconnector) {
		DRM_ERROR("Failed to found connector for link!");
		return false;
	}

	msgs = kzalloc(num * sizeof(struct i2c_msg), GFP_KERNEL);

	if (!msgs)
		return false;

	for (i = 0; i < num; i++) {
		msgs[i].flags = cmd->payloads[i].write ? I2C_M_RD : 0;
		msgs[i].addr = cmd->payloads[i].address;
		msgs[i].len = cmd->payloads[i].length;
		msgs[i].buf = cmd->payloads[i].data;
	}

	result = i2c_transfer(&aconnector->i2c->base, msgs, num) == num;

	kfree(msgs);

	return result;
}

void dm_helper_conn_log(struct dc_context *ctx,
		const struct dc_link *link,
		uint8_t *hex_data,
		int hex_data_count,
		enum conn_event event,
		const char *msg,
		...)
{
	struct amdgpu_device *adev = ctx->driver_context;
	struct drm_device *dev = adev->ddev;
	struct amdgpu_connector *aconnector = get_connector_for_link(dev, link);
	char buffer[CONN_MAX_LINE_SIZE] = { 0 };
	va_list args;
	int size;
	enum log_minor minor = event;

	va_start(args, msg);

	sprintf(buffer, "[%s] ", aconnector->base.name);

	size = strlen(buffer);

	size += dm_log_to_buffer(
		&buffer[size], CONN_MAX_LINE_SIZE, msg, args);

	if (buffer[strlen(buffer) - 1] == '\n') {
		buffer[strlen(buffer) - 1] = '\0';
		size--;
	}

	if (hex_data_count > (CONN_MAX_LINE_SIZE - size))
		return;

	if (hex_data) {
		int i;

		for (i = 0; i < hex_data_count; i++)
			sprintf(&buffer[size + i * 3], "%2.2X ", hex_data[i]);
	}

	strcat(buffer, "^\n");

	dal_logger_write(ctx->logger,
					LOG_MAJOR_CONNECTIVITY,
					minor,
					buffer);
	va_end(args);
}
