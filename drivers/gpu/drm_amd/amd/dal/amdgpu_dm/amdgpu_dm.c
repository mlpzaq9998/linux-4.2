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

#include "dm_services_types.h"
#include "dc.h"

#include "vid.h"
#include "amdgpu.h"
#include "atom.h"
#include "amdgpu_dm.h"
#include "amdgpu_dm_types.h"

#include "amd_shared.h"
#include "amdgpu_dm_irq.h"
#include "dm_helpers.h"

#ifdef CONFIG_DRM_AMDGPU_CIK
#include "dce_v8_0.h"
#endif
#include "dce_v10_0.h"
#include "dce_v11_0.h"

#include "ivsrcid/ivsrcid_vislands30.h"

#include <linux/module.h>
#include <linux/moduleparam.h>

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_dp_mst_helper.h>

/* Define variables here
 * These values will be passed to DAL for feature enable purpose
 * Disable ALL for HDMI light up
 * TODO: follow up if need this mechanism*/
struct dal_override_parameters display_param = {
	.bool_param_enable_mask = 0,
	.bool_param_values = 0,
};

/* Debug facilities */
#define AMDGPU_DM_NOT_IMPL(fmt, ...) \
	DRM_INFO("DM_NOT_IMPL: " fmt, ##__VA_ARGS__)

/*
 * dm_vblank_get_counter
 *
 * @brief
 * Get counter for number of vertical blanks
 *
 * @param
 * struct amdgpu_device *adev - [in] desired amdgpu device
 * int disp_idx - [in] which CRTC to get the counter from
 *
 * @return
 * Counter for vertical blanks
 */
static u32 dm_vblank_get_counter(struct amdgpu_device *adev, int crtc)
{
	if (crtc >= adev->mode_info.num_crtc)
		return 0;
	else {
		struct amdgpu_crtc *acrtc = adev->mode_info.crtcs[crtc];

		if (NULL == acrtc->target) {
			DRM_ERROR("dc_target is NULL for crtc '%d'!\n", crtc);
			return 0;
		}

		return dc_target_get_vblank_counter(acrtc->target);
	}
}

static int dm_crtc_get_scanoutpos(struct amdgpu_device *adev, int crtc,
					u32 *vbl, u32 *position)
{
	if ((crtc < 0) || (crtc >= adev->mode_info.num_crtc))
		return -EINVAL;
	else {
		struct amdgpu_crtc *acrtc = adev->mode_info.crtcs[crtc];

		if (NULL == acrtc->target) {
			DRM_ERROR("dc_target is NULL for crtc '%d'!\n", crtc);
			return 0;
		}

		return dc_target_get_scanoutpos(acrtc->target, vbl, position);
	}

	return 0;
}

static bool dm_is_idle(void *handle)
{
	/* XXX todo */
	return true;
}

static int dm_wait_for_idle(void *handle)
{
	/* XXX todo */
	return 0;
}

static int dm_soft_reset(void *handle)
{
	/* XXX todo */
	return 0;
}

static struct amdgpu_crtc *get_crtc_by_target(
	struct amdgpu_device *adev,
	const struct dc_target *dc_target)
{
	struct drm_device *dev = adev->ddev;
	struct drm_crtc *crtc;
	struct amdgpu_crtc *amdgpu_crtc;

	/*
	 * following if is check inherited from both functions where this one is
	 * used now. Need to be checked why it could happen.
	 */
	if (dc_target == NULL) {
		WARN_ON(1);
		return adev->mode_info.crtcs[0];
	}

	list_for_each_entry(crtc, &dev->mode_config.crtc_list, head) {
		amdgpu_crtc = to_amdgpu_crtc(crtc);

		if (amdgpu_crtc->target == dc_target)
			return amdgpu_crtc;
	}

	return NULL;
}

static void dm_pflip_high_irq(void *interrupt_params)
{
	struct amdgpu_flip_work *works;
	struct amdgpu_crtc *amdgpu_crtc;
	struct common_irq_params *irq_params = interrupt_params;
	struct amdgpu_device *adev = irq_params->adev;
	unsigned long flags;
	const struct dc *dc = irq_params->adev->dm.dc;
	const struct dc_target *dc_target =
			dc_get_target_on_irq_source(dc, irq_params->irq_src);

	amdgpu_crtc = get_crtc_by_target(adev, dc_target);

	/* IRQ could occur when in initial stage */
	/*TODO work and BO cleanup */
	if (amdgpu_crtc == NULL) {
		DRM_DEBUG_DRIVER("CRTC is null, returning.\n");
		return;
	}

	spin_lock_irqsave(&adev->ddev->event_lock, flags);
	works = amdgpu_crtc->pflip_works;

	if (amdgpu_crtc->pflip_status != AMDGPU_FLIP_SUBMITTED){
		DRM_DEBUG_DRIVER("amdgpu_crtc->pflip_status = %d !=AMDGPU_FLIP_SUBMITTED(%d) on crtc:%d[%p] \n",
						 amdgpu_crtc->pflip_status,
						 AMDGPU_FLIP_SUBMITTED,
						 amdgpu_crtc->crtc_id,
						 amdgpu_crtc);
		spin_unlock_irqrestore(&adev->ddev->event_lock, flags);
		return;
	}

	/* page flip completed. clean up */
	amdgpu_crtc->pflip_status = AMDGPU_FLIP_NONE;
	amdgpu_crtc->pflip_works = NULL;

	/* wakeup usersapce */
	if(works->event)
		drm_send_vblank_event(
			adev->ddev,
			amdgpu_crtc->crtc_id,
			works->event);

	spin_unlock_irqrestore(&adev->ddev->event_lock, flags);

	DRM_DEBUG_DRIVER("%s - crtc :%d[%p], pflip_stat:AMDGPU_FLIP_NONE, work: %p,\n",
					__func__, amdgpu_crtc->crtc_id, amdgpu_crtc, works);

	drm_crtc_vblank_put(&amdgpu_crtc->base);
	schedule_work(&works->unpin_work);
}

static void dm_crtc_high_irq(void *interrupt_params)
{
	struct common_irq_params *irq_params = interrupt_params;
	struct amdgpu_device *adev = irq_params->adev;
	const struct dc *dc = irq_params->adev->dm.dc;
	const struct dc_target *dc_target =
			dc_get_target_on_irq_source(dc, irq_params->irq_src);
	uint8_t crtc_index = 0;
	struct amdgpu_crtc *acrtc = get_crtc_by_target(adev, dc_target);

	if (acrtc)
		crtc_index = acrtc->crtc_id;

	drm_handle_vblank(adev->ddev, crtc_index);

}

static int dm_set_clockgating_state(void *handle,
		  enum amd_clockgating_state state)
{
	return 0;
}

static int dm_set_powergating_state(void *handle,
		  enum amd_powergating_state state)
{
	return 0;
}

/* Prototypes of private functions */
static int dm_early_init(void* handle);

static void hotplug_notify_work_func(struct work_struct *work)
{
	struct amdgpu_display_manager *dm = container_of(work, struct amdgpu_display_manager, mst_hotplug_work);
	struct drm_device *dev = dm->ddev;

	drm_kms_helper_hotplug_event(dev);
}

/* Init display KMS
 *
 * Returns 0 on success
 */
int amdgpu_dm_init(struct amdgpu_device *adev)
{
	struct dc_init_data init_data;
	adev->dm.ddev = adev->ddev;
	adev->dm.adev = adev;

	DRM_INFO("DAL is enabled\n");
	/* Zero all the fields */
	memset(&init_data, 0, sizeof(init_data));

	/* initialize DAL's lock (for SYNC context use) */
	spin_lock_init(&adev->dm.dal_lock);

	/* initialize DAL's mutex */
	mutex_init(&adev->dm.dal_mutex);

	if(amdgpu_dm_irq_init(adev)) {
		DRM_ERROR("amdgpu: failed to initialize DM IRQ support.\n");
		goto error;
	}

	init_data.display_param = display_param;

	init_data.asic_id.chip_family = adev->family;

	init_data.asic_id.pci_revision_id = adev->rev_id;
	init_data.asic_id.hw_internal_rev = adev->external_rev_id;

	init_data.asic_id.vram_width = adev->mc.vram_width;
	/* TODO: initialize init_data.asic_id.vram_type here!!!! */
	init_data.asic_id.atombios_base_address =
		adev->mode_info.atom_context->bios;
	init_data.asic_id.runtime_flags.flags.bits.SKIP_POWER_DOWN_ON_RESUME = 1;

	if ((adev->asic_type == CHIP_CARRIZO) ||
	    (adev->asic_type == CHIP_STONEY))
		init_data.asic_id.runtime_flags.flags.bits.GNB_WAKEUP_SUPPORTED = 1;

	init_data.driver = adev;

	adev->dm.cgs_device = amdgpu_cgs_create_device(adev);

	if (!adev->dm.cgs_device) {
		DRM_ERROR("amdgpu: failed to create cgs device.\n");
		goto error;
	}

	init_data.cgs_device = adev->dm.cgs_device;

	adev->dm.dal = NULL;

	/* enable gpu scaling in DAL */
	init_data.display_param.bool_param_enable_mask |=
		1 << DAL_PARAM_ENABLE_GPU_SCALING;
	init_data.display_param.bool_param_values |=
		1 << DAL_PARAM_ENABLE_GPU_SCALING;

	init_data.dce_environment = DCE_ENV_PRODUCTION_DRV;

	/* Display Core create. */
	adev->dm.dc = dc_create(&init_data);

	if (!adev->dm.dc)
		DRM_INFO("Display Core failed to initialize!\n");

	INIT_WORK(&adev->dm.mst_hotplug_work, hotplug_notify_work_func);

	if (amdgpu_dm_initialize_drm_device(adev)) {
		DRM_ERROR(
		"amdgpu: failed to initialize sw for display support.\n");
		goto error;
	}

	/* Update the actual used number of crtc */
	adev->mode_info.num_crtc = adev->dm.display_indexes_num;

	/* TODO: Add_display_info? */

	/* TODO use dynamic cursor width */
	adev->ddev->mode_config.cursor_width = 128;
	adev->ddev->mode_config.cursor_height = 128;

	if (drm_vblank_init(adev->ddev, adev->dm.display_indexes_num)) {
		DRM_ERROR(
		"amdgpu: failed to initialize sw for display support.\n");
		goto error;
	}

	DRM_INFO("KMS initialized.\n");

	return 0;
error:
	amdgpu_dm_fini(adev);

	return -1;
}

void amdgpu_dm_fini(struct amdgpu_device *adev)
{
	amdgpu_dm_destroy_drm_device(&adev->dm);
	/*
	 * TODO: pageflip, vlank interrupt
	 *
	 * amdgpu_dm_irq_fini(adev);
	 */

	if (adev->dm.cgs_device) {
		amdgpu_cgs_destroy_device(adev->dm.cgs_device);
		adev->dm.cgs_device = NULL;
	}

	/* DC Destroy TODO: Replace destroy DAL */
	{
		dc_destroy(&adev->dm.dc);
	}
	return;
}

/* moved from amdgpu_dm_kms.c */
void amdgpu_dm_destroy()
{
}

static int dm_sw_init(void *handle)
{
	return 0;
}

static int dm_sw_fini(void *handle)
{
	return 0;
}

static void detect_link_for_all_connectors(struct drm_device *dev)
{
	struct amdgpu_connector *aconnector;
	struct drm_connector *connector;

	drm_modeset_lock(&dev->mode_config.connection_mutex, NULL);

	list_for_each_entry(connector, &dev->mode_config.connector_list, head) {
		   aconnector = to_amdgpu_connector(connector);
		   if (aconnector->dc_link->type == dc_connection_mst_branch) {
			   DRM_INFO("DM_MST: starting TM on aconnector: %p [id: %d]\n",
						aconnector, aconnector->base.base.id);

				if (drm_dp_mst_topology_mgr_set_mst(&aconnector->mst_mgr, true) < 0) {
					DRM_ERROR("DM_MST: Failed to start MST\n");
					((struct dc_link *)aconnector->dc_link)->type = dc_connection_single;
				}
		   }
	}

	drm_modeset_unlock(&dev->mode_config.connection_mutex);
}

static void s3_handle_mst(struct drm_device *dev, bool suspend)
{
	struct amdgpu_connector *aconnector;
	struct drm_connector *connector;

	drm_modeset_lock(&dev->mode_config.connection_mutex, NULL);

	list_for_each_entry(connector, &dev->mode_config.connector_list, head) {
		   aconnector = to_amdgpu_connector(connector);
		   if (aconnector->dc_link->type == dc_connection_mst_branch &&
				   !aconnector->mst_port) {

			   if (suspend)
				   drm_dp_mst_topology_mgr_suspend(&aconnector->mst_mgr);
			   else
				   drm_dp_mst_topology_mgr_resume(&aconnector->mst_mgr);
		   }
	}

	drm_modeset_unlock(&dev->mode_config.connection_mutex);
}

static int dm_hw_init(void *handle)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;
	/* Create DAL display manager */
	amdgpu_dm_init(adev);

	amdgpu_dm_hpd_init(adev);

	detect_link_for_all_connectors(adev->ddev);

	return 0;
}

static int dm_hw_fini(void *handle)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	amdgpu_dm_hpd_fini(adev);

	amdgpu_dm_irq_fini(adev);

	return 0;
}

static int dm_suspend(void *handle)
{
	struct amdgpu_device *adev = handle;
	struct amdgpu_display_manager *dm = &adev->dm;
	int ret = 0;
	struct drm_crtc *crtc;

	s3_handle_mst(adev->ddev, true);

	/* flash all pending vblank events and turn interrupt off
	 * before disabling CRTCs. They will be enabled back in
	 * dm_display_resume
	 */
	drm_modeset_lock_all(adev->ddev);
	list_for_each_entry(crtc, &adev->ddev->mode_config.crtc_list, head) {
		struct amdgpu_crtc *acrtc = to_amdgpu_crtc(crtc);
		if (acrtc->target)
				drm_crtc_vblank_off(crtc);
	}
	drm_modeset_unlock_all(adev->ddev);

	amdgpu_dm_irq_suspend(adev);

	dc_set_power_state(
		dm->dc,
		DC_ACPI_CM_POWER_STATE_D3,
		DC_VIDEO_POWER_SUSPEND);

	return ret;
}

struct amdgpu_connector *amdgpu_dm_find_first_crct_matching_connector(
	struct drm_atomic_state *state,
	struct drm_crtc *crtc,
	bool from_state_var)
{
	uint32_t i;
	struct drm_connector_state *conn_state;
	struct drm_connector *connector;
	struct drm_crtc *crtc_from_state;

	for_each_connector_in_state(
		state,
		connector,
		conn_state,
		i) {
		crtc_from_state =
			from_state_var ?
				conn_state->crtc :
				connector->state->crtc;

		if (crtc_from_state == crtc)
			return to_amdgpu_connector(connector);
	}

	return NULL;
}

static int dm_display_resume(struct drm_device *ddev)
{
	int ret = 0;
	struct drm_connector *connector;

	struct drm_atomic_state *state = drm_atomic_state_alloc(ddev);
	struct drm_plane *plane;
	struct drm_crtc *crtc;
	struct amdgpu_connector *aconnector;
	struct drm_connector_state *conn_state;

	if (!state)
		return ENOMEM;

	state->acquire_ctx = ddev->mode_config.acquire_ctx;

	/* Construct an atomic state to restore previous display setting */

	/*
	 * Attach connectors to drm_atomic_state
	 * Should be done in the first place in order to make connectors
	 * available in state during crtc state processing. It is used for
	 * making decision if crtc should be disabled in case sink got
	 * disconnected.
	 *
	 * Connectors state crtc with NULL dc_sink should be cleared, because it
	 * will fail validation during commit
	 */
	list_for_each_entry(connector, &ddev->mode_config.connector_list, head) {
		aconnector = to_amdgpu_connector(connector);
		conn_state = drm_atomic_get_connector_state(state, connector);

		ret = PTR_ERR_OR_ZERO(conn_state);
		if (ret)
			goto err;
	}

	/* Attach crtcs to drm_atomic_state*/
	list_for_each_entry(crtc, &ddev->mode_config.crtc_list, head) {
		struct drm_crtc_state *crtc_state =
			drm_atomic_get_crtc_state(state, crtc);

		ret = PTR_ERR_OR_ZERO(crtc_state);
		if (ret)
			goto err;

		/* force a restore */
		crtc_state->mode_changed = true;
	}


	/* Attach planes to drm_atomic_state */
	list_for_each_entry(plane, &ddev->mode_config.plane_list, head) {

		struct drm_crtc *crtc;
		struct drm_gem_object *obj;
		struct drm_framebuffer *fb;
		struct amdgpu_framebuffer *afb;
		struct amdgpu_bo *rbo;
		int r;
		struct drm_plane_state *plane_state = drm_atomic_get_plane_state(state, plane);

		ret = PTR_ERR_OR_ZERO(plane_state);
		if (ret)
			goto err;

		crtc = plane_state->crtc;
		fb = plane_state->fb;

		if (!crtc || !crtc->state || !crtc->state->active)
			continue;

		if (!fb) {
			DRM_DEBUG_KMS("No FB bound\n");
			return 0;
		}

		/*
		 * Pin back the front buffers, cursor buffer was already pinned
		 * back in amdgpu_resume_kms
		 */

		afb = to_amdgpu_framebuffer(fb);

		obj = afb->obj;
		rbo = gem_to_amdgpu_bo(obj);
		r = amdgpu_bo_reserve(rbo, false);
		if (unlikely(r != 0))
		       return r;

		r = amdgpu_bo_pin(rbo, AMDGPU_GEM_DOMAIN_VRAM, NULL);

		amdgpu_bo_unreserve(rbo);

		if (unlikely(r != 0)) {
			DRM_ERROR("Failed to pin framebuffer\n");
			return r;
		}

	}


	/* Call commit internally with the state we just constructed */
	ret = drm_atomic_commit(state);
	if (!ret)
		return 0;

err:
	DRM_ERROR("Restoring old state failed with %i\n", ret);
	drm_atomic_state_free(state);

	return ret;
}

static int dm_resume(void *handle)
{
	struct amdgpu_device *adev = handle;
	struct amdgpu_display_manager *dm = &adev->dm;

	/* power on hardware */
	dc_set_power_state(
		dm->dc,
		DC_ACPI_CM_POWER_STATE_D0,
		DC_VIDEO_POWER_ON);

	return 0;
}

int amdgpu_dm_display_resume(struct amdgpu_device *adev )
{
	struct drm_device *ddev = adev->ddev;
	struct amdgpu_display_manager *dm = &adev->dm;
	struct amdgpu_connector *aconnector;
	struct drm_connector *connector;
	int ret = 0;
	struct drm_crtc *crtc;

	/* program HPD filter */
	dc_resume(dm->dc);

	/* On resume we need to  rewrite the MSTM control bits to enamble MST*/
	s3_handle_mst(ddev, false);

	/*
	 * early enable HPD Rx IRQ, should be done before set mode as short
	 * pulse interrupts are used for MST
	 */
	amdgpu_dm_irq_resume_early(adev);

	drm_modeset_lock_all(ddev);
	list_for_each_entry(crtc, &ddev->mode_config.crtc_list, head) {
		struct amdgpu_crtc *acrtc = to_amdgpu_crtc(crtc);
		if (acrtc->target)
				drm_crtc_vblank_on(crtc);
	}
	drm_modeset_unlock_all(ddev);

	/* Do detection*/
	list_for_each_entry(connector,
			&ddev->mode_config.connector_list, head) {
		aconnector = to_amdgpu_connector(connector);

		/*
		 * this is the case when traversing through already created
		 * MST connectors, should be skipped
		 */
		if (aconnector->mst_port)
			continue;

		dc_link_detect(aconnector->dc_link, false);
		aconnector->dc_sink = NULL;
		amdgpu_dm_update_connector_after_detect(aconnector);
	}

	drm_modeset_lock_all(ddev);
	ret = dm_display_resume(ddev);
	drm_modeset_unlock_all(ddev);

	amdgpu_dm_irq_resume(adev);

	return ret;
}

const struct amd_ip_funcs amdgpu_dm_funcs = {
	.name = "dm",
	.early_init = dm_early_init,
	.late_init = NULL,
	.sw_init = dm_sw_init,
	.sw_fini = dm_sw_fini,
	.hw_init = dm_hw_init,
	.hw_fini = dm_hw_fini,
	.suspend = dm_suspend,
	.resume = dm_resume,
	.is_idle = dm_is_idle,
	.wait_for_idle = dm_wait_for_idle,
	.soft_reset = dm_soft_reset,
	.set_clockgating_state = dm_set_clockgating_state,
	.set_powergating_state = dm_set_powergating_state,
};

/* TODO: it is temporary non-const, should fixed later */
static struct drm_mode_config_funcs amdgpu_dm_mode_funcs = {
	.atomic_check = amdgpu_dm_atomic_check,
	.atomic_commit = amdgpu_dm_atomic_commit
};

void amdgpu_dm_update_connector_after_detect(
	struct amdgpu_connector *aconnector)
{
	struct drm_connector *connector = &aconnector->base;
	struct drm_device *dev = connector->dev;
	const struct dc_sink *sink;

	/* MST handled by drm_mst framework */
	if (aconnector->mst_mgr.mst_state == true)
		return;

	sink = aconnector->dc_link->local_sink;

	/*
	 * TODO: temporary guard to look for proper fix
	 * if this sink is MST sink, we should not do anything
	 */
	if (sink && sink->sink_signal == SIGNAL_TYPE_DISPLAY_PORT_MST)
		return;

	if (aconnector->dc_sink == sink) {
		/* We got a DP short pulse (Link Loss, DP CTS, etc...).
		 * Do nothing!! */
		DRM_INFO("DCHPD: connector_id=%d: dc_sink didn't change.\n",
				aconnector->connector_id);
		return;
	}

	DRM_INFO("DCHPD: connector_id=%d: Old sink=%p New sink=%p\n",
		aconnector->connector_id, aconnector->dc_sink, sink);

	mutex_lock(&dev->mode_config.mutex);

	/* 1. Update status of the drm connector
	 * 2. Send an event and let userspace tell us what to do */
	if (sink) {
		/* TODO: check if we still need the S3 mode update workaround.
		 * If yes, put it here. */

		aconnector->dc_sink = sink;
		if (sink->dc_edid.length == 0)
			aconnector->edid = NULL;
		else {
			aconnector->edid =
				(struct edid *) sink->dc_edid.raw_edid;
			drm_mode_connector_update_edid_property(connector,
					aconnector->edid);
		}
	} else {
		drm_mode_connector_update_edid_property(connector, NULL);
		aconnector->num_modes = 0;
		aconnector->dc_sink = NULL;
	}

	mutex_unlock(&dev->mode_config.mutex);
}

static void handle_hpd_irq(void *param)
{
	struct amdgpu_connector *aconnector = (struct amdgpu_connector *)param;
	struct drm_connector *connector = &aconnector->base;
	struct drm_device *dev = connector->dev;

	/* In case of failure or MST no need to update connector status or notify the OS
	 * since (for MST case) MST does this in it's own context.
	 */
	if (dc_link_detect(aconnector->dc_link, false)) {
		amdgpu_dm_update_connector_after_detect(aconnector);

		drm_modeset_lock_all(dev);
		dm_restore_drm_connector_state(dev, connector);
		drm_modeset_unlock_all(dev);

		drm_kms_helper_hotplug_event(dev);
	}

}

static void handle_hpd_rx_irq(void *param)
{
	struct amdgpu_connector *aconnector = (struct amdgpu_connector *)param;
	struct drm_connector *connector = &aconnector->base;
	struct drm_device *dev = connector->dev;
	bool is_mst_root_connector = aconnector->mst_mgr.mst_state;

	if (dc_link_handle_hpd_rx_irq(aconnector->dc_link) &&
			!is_mst_root_connector) {
		/* Downstream Port status changed. */
		if (dc_link_detect(aconnector->dc_link, false)) {
			amdgpu_dm_update_connector_after_detect(aconnector);

			drm_modeset_lock_all(dev);
			dm_restore_drm_connector_state(dev, connector);
			drm_modeset_unlock_all(dev);

			drm_kms_helper_hotplug_event(dev);
		}
	}

	if (is_mst_root_connector)
		dm_helpers_dp_mst_handle_mst_hpd_rx_irq(param);
}

static void register_hpd_handlers(struct amdgpu_device *adev)
{
	struct drm_device *dev = adev->ddev;
	struct drm_connector *connector;
	struct amdgpu_connector *aconnector;
	const struct dc_link *dc_link;
	struct dc_interrupt_params int_params = {0};

	int_params.requested_polarity = INTERRUPT_POLARITY_DEFAULT;
	int_params.current_polarity = INTERRUPT_POLARITY_DEFAULT;

	list_for_each_entry(connector,
			&dev->mode_config.connector_list, head)	{

		aconnector = to_amdgpu_connector(connector);
		dc_link = aconnector->dc_link;

		if (DC_IRQ_SOURCE_INVALID != dc_link->irq_source_hpd) {
			int_params.int_context = INTERRUPT_LOW_IRQ_CONTEXT;
			int_params.irq_source = dc_link->irq_source_hpd;

			amdgpu_dm_irq_register_interrupt(adev, &int_params,
					handle_hpd_irq,
					(void *) aconnector);
		}

		if (DC_IRQ_SOURCE_INVALID != dc_link->irq_source_hpd_rx) {

			/* Also register for DP short pulse (hpd_rx). */
			int_params.int_context = INTERRUPT_LOW_IRQ_CONTEXT;
			int_params.irq_source =	dc_link->irq_source_hpd_rx;

			amdgpu_dm_irq_register_interrupt(adev, &int_params,
					handle_hpd_rx_irq,
					(void *) aconnector);
		}
	}
}

/* Register IRQ sources and initialize IRQ callbacks */
static int dce110_register_irq_handlers(struct amdgpu_device *adev)
{
	struct dc *dc = adev->dm.dc;
	struct common_irq_params *c_irq_params;
	struct dc_interrupt_params int_params = {0};
	int r;
	int i;

	int_params.requested_polarity = INTERRUPT_POLARITY_DEFAULT;
	int_params.current_polarity = INTERRUPT_POLARITY_DEFAULT;

	/* Actions of amdgpu_irq_add_id():
	 * 1. Register a set() function with base driver.
	 *    Base driver will call set() function to enable/disable an
	 *    interrupt in DC hardware.
	 * 2. Register amdgpu_dm_irq_handler().
	 *    Base driver will call amdgpu_dm_irq_handler() for ALL interrupts
	 *    coming from DC hardware.
	 *    amdgpu_dm_irq_handler() will re-direct the interrupt to DC
	 *    for acknowledging and handling. */

	for (i = VISLANDS30_IV_SRCID_D1_V_UPDATE_INT;
			i <= VISLANDS30_IV_SRCID_D6_V_UPDATE_INT; i += 2) {
		r = amdgpu_irq_add_id(adev, i, &adev->crtc_irq);
		if (r) {
			DRM_ERROR("Failed to add crtc irq id!\n");
			return r;
		}

		int_params.int_context = INTERRUPT_HIGH_IRQ_CONTEXT;
		int_params.irq_source =
			dc_interrupt_to_irq_source(dc, i, 0);

		c_irq_params = &adev->dm.vupdate_params[int_params.irq_source - DC_IRQ_SOURCE_VUPDATE1];

		c_irq_params->adev = adev;
		c_irq_params->irq_src = int_params.irq_source;

		amdgpu_dm_irq_register_interrupt(adev, &int_params,
				dm_crtc_high_irq, c_irq_params);
	}

	for (i = VISLANDS30_IV_SRCID_D1_GRPH_PFLIP;
			i <= VISLANDS30_IV_SRCID_D6_GRPH_PFLIP; i += 2) {
		r = amdgpu_irq_add_id(adev, i, &adev->pageflip_irq);
		if (r) {
			DRM_ERROR("Failed to add page flip irq id!\n");
			return r;
		}

		int_params.int_context = INTERRUPT_HIGH_IRQ_CONTEXT;
		int_params.irq_source =
			dc_interrupt_to_irq_source(dc, i, 0);

		c_irq_params = &adev->dm.pflip_params[int_params.irq_source - DC_IRQ_SOURCE_PFLIP_FIRST];

		c_irq_params->adev = adev;
		c_irq_params->irq_src = int_params.irq_source;

		amdgpu_dm_irq_register_interrupt(adev, &int_params,
				dm_pflip_high_irq, c_irq_params);

	}

	/* HPD */
	r = amdgpu_irq_add_id(adev, VISLANDS30_IV_SRCID_HOTPLUG_DETECT_A,
			&adev->hpd_irq);
	if (r) {
		DRM_ERROR("Failed to add hpd irq id!\n");
		return r;
	}

	register_hpd_handlers(adev);

	return 0;
}

static int amdgpu_dm_mode_config_init(struct amdgpu_device *adev)
{
	int r;

	adev->mode_info.mode_config_initialized = true;

	amdgpu_dm_mode_funcs.fb_create =
		amdgpu_mode_funcs.fb_create;
	amdgpu_dm_mode_funcs.output_poll_changed =
		amdgpu_mode_funcs.output_poll_changed;

	adev->ddev->mode_config.funcs = (void *)&amdgpu_dm_mode_funcs;

	adev->ddev->mode_config.max_width = 16384;
	adev->ddev->mode_config.max_height = 16384;

	adev->ddev->mode_config.preferred_depth = 24;
	adev->ddev->mode_config.prefer_shadow = 1;

	adev->ddev->mode_config.fb_base = adev->mc.aper_base;

	r = amdgpu_modeset_create_props(adev);
	if (r)
		return r;

	return 0;
}

#if defined(CONFIG_BACKLIGHT_CLASS_DEVICE) ||\
	defined(CONFIG_BACKLIGHT_CLASS_DEVICE_MODULE)

static int amdgpu_dm_backlight_update_status(struct backlight_device *bd)
{
	struct amdgpu_display_manager *dm = bl_get_data(bd);

	if (dc_link_set_backlight_level(dm->backlight_link,
			bd->props.brightness))
		return 0;
	else
		return 1;
}

static int amdgpu_dm_backlight_get_brightness(struct backlight_device *bd)
{
	return bd->props.brightness;
}

static const struct backlight_ops amdgpu_dm_backlight_ops = {
	.get_brightness = amdgpu_dm_backlight_get_brightness,
	.update_status	= amdgpu_dm_backlight_update_status,
};

void amdgpu_dm_register_backlight_device(struct amdgpu_display_manager *dm)
{
	char bl_name[16];
	struct backlight_properties props = { 0 };

	props.max_brightness = AMDGPU_MAX_BL_LEVEL;
	props.type = BACKLIGHT_RAW;

	snprintf(bl_name, sizeof(bl_name), "amdgpu_bl%d",
			dm->adev->ddev->primary->index);

	dm->backlight_dev = backlight_device_register(bl_name,
			dm->adev->ddev->dev,
			dm,
			&amdgpu_dm_backlight_ops,
			&props);

	if (NULL == dm->backlight_dev)
		DRM_ERROR("DM: Backlight registration failed!\n");
	else
		DRM_INFO("DM: Registered Backlight device: %s\n", bl_name);
}

#endif

/* In this architecture, the association
 * connector -> encoder -> crtc
 * id not really requried. The crtc and connector will hold the
 * display_index as an abstraction to use with DAL component
 *
 * Returns 0 on success
 */
int amdgpu_dm_initialize_drm_device(struct amdgpu_device *adev)
{
	struct amdgpu_display_manager *dm = &adev->dm;
	uint32_t i;
	struct amdgpu_connector *aconnector;
	struct amdgpu_encoder *aencoder;
	struct amdgpu_crtc *acrtc;
	uint32_t link_cnt;

	link_cnt = dm->dc->caps.max_links;

	if (amdgpu_dm_mode_config_init(dm->adev)) {
		DRM_ERROR("DM: Failed to initialize mode config\n");
		return -1;
	}

	for (i = 0; i < dm->dc->caps.max_targets; i++) {
		acrtc = kzalloc(sizeof(struct amdgpu_crtc), GFP_KERNEL);
		if (!acrtc)
			goto fail;

		if (amdgpu_dm_crtc_init(
			dm,
			acrtc,
			i)) {
			DRM_ERROR("KMS: Failed to initialize crtc\n");
			kfree(acrtc);
			goto fail;
		}
	}

	dm->display_indexes_num = dm->dc->caps.max_targets;

	/* loops over all connectors on the board */
	for (i = 0; i < link_cnt; i++) {

		if (i > AMDGPU_DM_MAX_DISPLAY_INDEX) {
			DRM_ERROR(
				"KMS: Cannot support more than %d display indexes\n",
					AMDGPU_DM_MAX_DISPLAY_INDEX);
			continue;
		}

		aconnector = kzalloc(sizeof(*aconnector), GFP_KERNEL);
		if (!aconnector)
			goto fail;

		aencoder = kzalloc(sizeof(*aencoder), GFP_KERNEL);
		if (!aencoder) {
			goto fail_free_connector;
		}

		if (amdgpu_dm_encoder_init(dm->ddev, aencoder, i)) {
			DRM_ERROR("KMS: Failed to initialize encoder\n");
			goto fail_free_encoder;
		}

		if (amdgpu_dm_connector_init(dm, aconnector, i, aencoder)) {
			DRM_ERROR("KMS: Failed to initialize connector\n");
			goto fail_free_connector;
		}

		if (dc_link_detect(dc_get_link_at_index(dm->dc, i), true))
			amdgpu_dm_update_connector_after_detect(
				aconnector);
	}

	/* Software is initialized. Now we can register interrupt handlers. */
	switch (adev->asic_type) {
	case CHIP_BONAIRE:
	case CHIP_HAWAII:
	case CHIP_TONGA:
	case CHIP_FIJI:
	case CHIP_CARRIZO:
	case CHIP_STONEY:
#if defined(CONFIG_DRM_AMD_DAL_DCE11_2)
	case CHIP_POLARIS11:
	case CHIP_POLARIS10:
#endif
		if (dce110_register_irq_handlers(dm->adev)) {
			DRM_ERROR("DM: Failed to initialize IRQ\n");
			return -1;
		}
		break;
	default:
		DRM_ERROR("Usupported ASIC type: 0x%X\n", adev->asic_type);
		return -1;
	}

	drm_mode_config_reset(dm->ddev);

	return 0;
fail_free_encoder:
	kfree(aencoder);
fail_free_connector:
	kfree(aconnector);
fail:
	return -1;
}

void amdgpu_dm_destroy_drm_device(struct amdgpu_display_manager *dm)
{
	drm_mode_config_cleanup(dm->ddev);
	return;
}

/******************************************************************************
 * amdgpu_display_funcs functions
 *****************************************************************************/

/**
 * dm_bandwidth_update - program display watermarks
 *
 * @adev: amdgpu_device pointer
 *
 * Calculate and program the display watermarks and line buffer allocation.
 */
static void dm_bandwidth_update(struct amdgpu_device *adev)
{
	AMDGPU_DM_NOT_IMPL("%s\n", __func__);
}

static void dm_set_backlight_level(struct amdgpu_encoder *amdgpu_encoder,
				     u8 level)
{
	/* TODO: translate amdgpu_encoder to display_index and call DAL */
	AMDGPU_DM_NOT_IMPL("%s\n", __func__);
}

static u8 dm_get_backlight_level(struct amdgpu_encoder *amdgpu_encoder)
{
	/* TODO: translate amdgpu_encoder to display_index and call DAL */
	AMDGPU_DM_NOT_IMPL("%s\n", __func__);
	return 0;
}

/******************************************************************************
 * Page Flip functions
 ******************************************************************************/

/**
 * dm_page_flip - called by amdgpu_flip_work_func(), which is triggered
 *			via DRM IOCTL, by user mode.
 *
 * @adev: amdgpu_device pointer
 * @crtc_id: crtc to cleanup pageflip on
 * @crtc_base: new address of the crtc (GPU MC address)
 *
 * Does the actual pageflip (surface address update).
 */
static void dm_page_flip(struct amdgpu_device *adev,
			int crtc_id, u64 crtc_base)
{
	struct amdgpu_crtc *acrtc;
	struct dc_target *target;
	struct dc_flip_addrs addr = { {0} };

	/*
	 * TODO risk of concurrency issues
	 *
	 * This should guarded by the dal_mutex but we can't do this since the
	 * caller uses a spin_lock on event_lock.
	 *
	 * If we wait on the dal_mutex a second page flip interrupt might come,
	 * spin on the event_lock, disabling interrupts while it does so. At
	 * this point the core can no longer be pre-empted and return to the
	 * thread that waited on the dal_mutex and we're deadlocked.
	 *
	 * With multiple cores the same essentially happens but might just take
	 * a little longer to lock up all cores.
	 *
	 * The reason we should lock on dal_mutex is so that we can be sure
	 * nobody messes with acrtc->target after we read and check its value.
	 *
	 * We might be able to fix our concurrency issues with a work queue
	 * where we schedule all work items (mode_set, page_flip, etc.) and
	 * execute them one by one. Care needs to be taken to still deal with
	 * any potential concurrency issues arising from interrupt calls.
	 */

	acrtc = adev->mode_info.crtcs[crtc_id];
	target = acrtc->target;

	/*
	 * Received a page flip call after the display has been reset.
	 * Just return in this case. Everything should be clean-up on reset.
	 */

	if (!target) {
		WARN_ON(1);
		return;
	}

	addr.address.grph.addr.low_part = lower_32_bits(crtc_base);
	addr.address.grph.addr.high_part = upper_32_bits(crtc_base);

	DRM_DEBUG_DRIVER("%s Flipping to hi: 0x%x, low: 0x%x \n",
			 __func__,
			 addr.address.grph.addr.high_part,
			 addr.address.grph.addr.low_part);

	dc_flip_surface_addrs(
			adev->dm.dc,
			dc_target_get_status(target)->surfaces,
			&addr, 1);
}

#ifdef CONFIG_DRM_AMDGPU_CIK
static const struct amdgpu_display_funcs dm_dce_v8_0_display_funcs = {
	.set_vga_render_state = dce_v8_0_set_vga_render_state,
	.bandwidth_update = dm_bandwidth_update, /* called unconditionally */
	.vblank_get_counter = dm_vblank_get_counter,/* called unconditionally */
	.vblank_wait = NULL,
	.is_display_hung = NULL, /* not called anywhere */
	.backlight_set_level =
		dm_set_backlight_level,/* called unconditionally */
	.backlight_get_level =
		dm_get_backlight_level,/* called unconditionally */
	.hpd_sense = NULL,/* called unconditionally */
	.hpd_set_polarity = NULL, /* called unconditionally */
	.hpd_get_gpio_reg = NULL, /* VBIOS parsing. DAL does it. */
	.page_flip = dm_page_flip, /* called unconditionally */
	.page_flip_get_scanoutpos =
		dm_crtc_get_scanoutpos,/* called unconditionally */
	.add_encoder = NULL, /* VBIOS parsing. DAL does it. */
	.add_connector = NULL, /* VBIOS parsing. DAL does it. */
	.stop_mc_access = dce_v8_0_stop_mc_access, /* called unconditionally */
	.resume_mc_access = dce_v8_0_resume_mc_access, /* called unconditionally */
};
#endif

static const struct amdgpu_display_funcs dm_dce_v10_0_display_funcs = {
	.set_vga_render_state = dce_v10_0_set_vga_render_state,
	.bandwidth_update = dm_bandwidth_update, /* called unconditionally */
	.vblank_get_counter = dm_vblank_get_counter,/* called unconditionally */
	.vblank_wait = NULL,
	.is_display_hung = NULL, /* not called anywhere */
	.backlight_set_level =
		dm_set_backlight_level,/* called unconditionally */
	.backlight_get_level =
		dm_get_backlight_level,/* called unconditionally */
	.hpd_sense = NULL,/* called unconditionally */
	.hpd_set_polarity = NULL, /* called unconditionally */
	.hpd_get_gpio_reg = NULL, /* VBIOS parsing. DAL does it. */
	.page_flip = dm_page_flip, /* called unconditionally */
	.page_flip_get_scanoutpos =
		dm_crtc_get_scanoutpos,/* called unconditionally */
	.add_encoder = NULL, /* VBIOS parsing. DAL does it. */
	.add_connector = NULL, /* VBIOS parsing. DAL does it. */
	.stop_mc_access = dce_v10_0_stop_mc_access, /* called unconditionally */
	.resume_mc_access = dce_v10_0_resume_mc_access, /* called unconditionally */
};

static const struct amdgpu_display_funcs dm_dce_v11_0_display_funcs = {
	.set_vga_render_state = dce_v11_0_set_vga_render_state,
	.bandwidth_update = dm_bandwidth_update, /* called unconditionally */
	.vblank_get_counter = dm_vblank_get_counter,/* called unconditionally */
	.vblank_wait = NULL,
	.is_display_hung = NULL, /* not called anywhere */
	.backlight_set_level =
		dm_set_backlight_level,/* called unconditionally */
	.backlight_get_level =
		dm_get_backlight_level,/* called unconditionally */
	.hpd_sense = NULL,/* called unconditionally */
	.hpd_set_polarity = NULL, /* called unconditionally */
	.hpd_get_gpio_reg = NULL, /* VBIOS parsing. DAL does it. */
	.page_flip = dm_page_flip, /* called unconditionally */
	.page_flip_get_scanoutpos =
		dm_crtc_get_scanoutpos,/* called unconditionally */
	.add_encoder = NULL, /* VBIOS parsing. DAL does it. */
	.add_connector = NULL, /* VBIOS parsing. DAL does it. */
	.stop_mc_access = dce_v11_0_stop_mc_access, /* called unconditionally */
	.resume_mc_access = dce_v11_0_resume_mc_access, /* called unconditionally */
};

#if defined(CONFIG_DEBUG_KERNEL_DAL)

static ssize_t s3_debug_store(
	struct device *device,
	struct device_attribute *attr,
	const char *buf,
	size_t count)
{
	int ret;
	int s3_state;
	struct pci_dev *pdev = to_pci_dev(device);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);
	struct amdgpu_device *adev = drm_dev->dev_private;

	ret = kstrtoint(buf, 0, &s3_state);

	if (ret == 0) {
		if (s3_state) {
			dm_resume(adev);
			amdgpu_dm_display_resume(adev);
			drm_kms_helper_hotplug_event(adev->ddev);
		} else
			dm_suspend(adev);
	}

	return ret == 0 ? count : 0;
}

DEVICE_ATTR_WO(s3_debug);

#endif

static int dm_early_init(void *handle)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)handle;

	amdgpu_dm_set_irq_funcs(adev);

	switch (adev->asic_type) {
	case CHIP_BONAIRE:
	case CHIP_HAWAII:
		adev->mode_info.num_crtc = 6;
		adev->mode_info.num_hpd = 6;
		adev->mode_info.num_dig = 6;
#ifdef CONFIG_DRM_AMDGPU_CIK
		if (adev->mode_info.funcs == NULL)
			adev->mode_info.funcs = &dm_dce_v8_0_display_funcs;
#endif
		break;
	case CHIP_FIJI:
	case CHIP_TONGA:
		adev->mode_info.num_crtc = 6;
		adev->mode_info.num_hpd = 6;
		adev->mode_info.num_dig = 7;
		if (adev->mode_info.funcs == NULL)
			adev->mode_info.funcs = &dm_dce_v10_0_display_funcs;
		break;
	case CHIP_CARRIZO:
		adev->mode_info.num_crtc = 3;
		adev->mode_info.num_hpd = 6;
		adev->mode_info.num_dig = 9;
		if (adev->mode_info.funcs == NULL)
			adev->mode_info.funcs = &dm_dce_v11_0_display_funcs;
		break;
	case CHIP_STONEY:
		adev->mode_info.num_crtc = 2;
		adev->mode_info.num_hpd = 6;
		adev->mode_info.num_dig = 9;
		if (adev->mode_info.funcs == NULL)
			adev->mode_info.funcs = &dm_dce_v11_0_display_funcs;
		break;
#if defined(CONFIG_DRM_AMD_DAL_DCE11_2)
	case CHIP_POLARIS11:
		adev->mode_info.num_crtc = 5;
		adev->mode_info.num_hpd = 5;
		adev->mode_info.num_dig = 5;
		if (adev->mode_info.funcs == NULL)
			adev->mode_info.funcs = &dm_dce_v11_0_display_funcs;
		break;
	case CHIP_POLARIS10:
		adev->mode_info.num_crtc = 6;
		adev->mode_info.num_hpd = 6;
		adev->mode_info.num_dig = 6;
		if (adev->mode_info.funcs == NULL)
			adev->mode_info.funcs = &dm_dce_v11_0_display_funcs;
		break;
#endif
	default:
		DRM_ERROR("Usupported ASIC type: 0x%X\n", adev->asic_type);
		return -EINVAL;
	}

	/* Note: Do NOT change adev->audio_endpt_rreg and
	 * adev->audio_endpt_wreg because they are initialised in
	 * amdgpu_device_init() */
#if defined(CONFIG_DEBUG_KERNEL_DAL)
	device_create_file(
		adev->ddev->dev,
		&dev_attr_s3_debug);
#endif

	return 0;
}

bool amdgpu_dm_acquire_dal_lock(struct amdgpu_display_manager *dm)
{
	/* TODO */
	return true;
}

bool amdgpu_dm_release_dal_lock(struct amdgpu_display_manager *dm)
{
	/* TODO */
	return true;
}


