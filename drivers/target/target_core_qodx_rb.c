/*******************************************************************************
 * Filename:  target_core_qodx_rb.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 ****************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/in.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#include <asm/unaligned.h>
#include <linux/rbtree_augmented.h>
#include <linux/random.h>
#include "target_core_qodx_lib.h"
#include "target_core_qodx_scsi.h"

static DEFINE_SPINLOCK(tpc_tpg_lock);
struct rb_root tpc_tpg_root = RB_ROOT;

/**/
extern struct kmem_cache *odx_cmd_data_cache;
extern struct kmem_cache *odx_tpg_data_cache;
extern struct kmem_cache *token512b_cache;
extern struct kmem_cache *odx_token_data_cache;

/**/
static void __odx_rb_del_tpg_cmd(
	struct tpc_tpg_data *p
	)
{
	struct rb_node *cmd_n = NULL, *next_cmd_n = NULL;
	struct tpc_cmd_data *tc_p = NULL, *tmp_tc_p = NULL;
	LIST_HEAD(del_list);
		
	spin_lock_bh(&p->cmd_root_lock);

	cmd_n = rb_first(&p->cmd_root);

	while (cmd_n) {
		tc_p = rb_entry(cmd_n, struct tpc_cmd_data, node);

		do {
			if (atomic_read(&tc_p->ref_count) == 1)
				break;

			pr_warn("tpc cmd (list id:0x%x) refcount not 1, "
				"it is still using by someone, "
				"wait next chance\n", tc_p->reg_data.list_id);

			spin_unlock_bh(&p->cmd_root_lock);
			cpu_relax();
			spin_lock_bh(&p->cmd_root_lock);
		} while(1);

		pr_debug("%s: del cmd:0x%p from rb tree\n", __func__, tc_p);

		/* if call RB_CLEAR_NODE() after rb_erase() while we use
		 * rb_first() + rb_next() to retrieve each node here, it will
		 * set parent node to itself, so need to get next node first ...
		 */
		next_cmd_n = rb_next(cmd_n);
		rb_erase(&tc_p->node, &p->cmd_root);
		RB_CLEAR_NODE(&tc_p->node);
		cmd_n = next_cmd_n;

		list_add_tail(&tc_p->del_node, &del_list);

	}
	spin_unlock_bh(&p->cmd_root_lock);

	list_for_each_entry_safe(tc_p, tmp_tc_p, &del_list, del_node)
		kmem_cache_free(odx_cmd_data_cache, tc_p);

}

static void __odx_rb_del_tpg_token(
	struct tpc_tpg_data *p
	)
{
	struct rb_node *token_n = NULL, *next_token_n = NULL;
	struct tpc_token_data *token_p = NULL;
	LIST_HEAD(del_list);

	spin_lock_bh(&p->token_root_lock);

	token_n = rb_first(&p->token_root);

	while (token_n) {
		token_p = rb_entry(token_n, struct tpc_token_data, node);

		do {
			if (atomic_read(&token_p->ref_count) == 1)
				break;
	
			pr_warn("tpc token (list id:0x%x) refcount not 1, "
				"it is still using by someone, "
				"wait next chance\n", token_p->reg_data.list_id);
	
			spin_unlock_bh(&p->token_root_lock);

			__odx_cmpxchg_token_status(token_p, O_TOKEN_ALIVE, O_TOKEN_DELETED);
			cpu_relax();
			spin_lock_bh(&p->token_root_lock);
		} while(1);

		/* if call RB_CLEAR_NODE() after rb_erase() while we use
		 * rb_first() + rb_next() to retrieve each node here, it will
		 * set parent node to itself, so need to get next node first ...
		 */
		next_token_n = rb_next(token_n);
		rb_erase(&token_p->node, &p->token_root);
		RB_CLEAR_NODE(&token_p->node);
		token_n = next_token_n;

		list_add_tail(&token_p->del_node, &del_list);

	}

	spin_unlock_bh(&p->token_root_lock);

	__odx_free_token_lists(&del_list);

}

static void __odx_rb_del_tpg(
	struct tpc_tpg_data *p
	)
{
//	__odx_rb_del_tpg_cmd(p);
	__odx_rb_del_tpg_token(p);
}

static struct tpc_cmd_data *__odx_rb_cmd_alloc(
	struct tpc_tpg_data *tpg_p,
	struct __reg_data *reg_data
	)
{
	struct tpc_cmd_data *p = NULL;

	p = kmem_cache_zalloc(odx_cmd_data_cache, GFP_KERNEL);
	if (!p)
		return NULL;

	memcpy(&p->reg_data, reg_data, sizeof(struct __reg_data));

	p->tpg_p = tpg_p;
	atomic_set(&p->cmd_status, T_CMD_NOT_START);
	atomic_set(&p->cmd_asked, CMD_ASKED_NOTHING);
	spin_lock_init(&p->cmd_asked_act_lock);
	spin_lock_init(&p->status_lock);
	spin_lock_init(&p->transfer_count_lock);
	atomic_set(&p->ref_count, 1);
	INIT_LIST_HEAD(&p->del_node);

	return p;
}

static struct tpc_tpg_data *__odx_rb_tpg_alloc(
	u64 tpg_id_hi,
	u64 tpg_id_lo
	)
{
	struct tpc_tpg_data *p = NULL;

	p = kmem_cache_zalloc(odx_tpg_data_cache, GFP_KERNEL);
	if (!p)
		return NULL;

	p->id_hi = tpg_id_hi;
	p->id_lo = tpg_id_lo;
	p->cmd_root = RB_ROOT;
	p->token_root = RB_ROOT;
	spin_lock_init(&p->cmd_root_lock);
	spin_lock_init(&p->token_root_lock);
	atomic_set(&p->ref_count, 1);
	return p;
}

struct tpc_token_data *odx_rb_token_find(
	struct tpc_tpg_data *tpg_p,
	u64 cmd_id_hi, 
	u64 cmd_id_lo, 
	u64 initiator_id_hi, 
	u64 initiator_id_lo,
	bool monitor_cp_req
	)
{
	struct rb_root root = tpg_p->token_root;
	struct rb_node *n = root.rb_node;
	struct tpc_token_data *data = NULL;
	struct __reg_data *reg_d = NULL;
	int ret;
	RC rc;

	while (n) {
		data = rb_entry(n, struct tpc_token_data, node);
		reg_d = &data->reg_data; 

		if ((cmd_id_hi < reg_d->cmd_id_hi)
		|| ((cmd_id_hi == reg_d->cmd_id_hi) 
			&& (cmd_id_lo < reg_d->cmd_id_lo))
		)
			n = n->rb_left;
		else {
			if ((cmd_id_hi == reg_d->cmd_id_hi) 
				&& (cmd_id_lo == reg_d->cmd_id_lo)
			)
			{
				/* want check initiator id ? */
				if (initiator_id_hi && initiator_id_lo) {
					if ((initiator_id_hi != reg_d->initiator_id_hi) 
					|| (initiator_id_lo != reg_d->initiator_id_lo)
					)
						goto next_node;
				}

				ret = __odx_is_token_invalid(data, &rc);
				if (ret != 0) {
					if (!monitor_cp_req)
						return NULL;
					else {
						pr_warn("find token (id:0x%x, sac:0x%x), "
						"req comes from monitor cp\n",
						reg_d->list_id, reg_d->sac);
					}
				}

				pr_debug("found token (0x%p), (id:0x%x) by "
					"cmd id(hi):0x%llx, cmd id(lo):0x%llx, "
					"initiator id(hi):0x%llx, "
					"initiator id(lo):0x%llx\n", 
					data, reg_d->list_id, 
					(unsigned long long)cmd_id_hi, 
					(unsigned long long)cmd_id_lo,
					(unsigned long long)initiator_id_hi, 
					(unsigned long long)initiator_id_lo);

				return data;
			}
next_node:
			n = n->rb_right;
		}
	}
	return NULL;

}


struct tpc_token_data *odx_rb_token_get(
	struct tpc_tpg_data *tpg_p,
	u64 cmd_id_hi, 
	u64 cmd_id_lo, 
	u64 initiator_id_hi, 
	u64 initiator_id_lo,
	bool monitor_cp_req
	)
{
	struct tpc_token_data *token_p = NULL;
	 
	if (!tpg_p)
		return NULL;
	 
	spin_lock_bh(&tpg_p->token_root_lock);
	 
	token_p = odx_rb_token_find(tpg_p, cmd_id_hi, cmd_id_lo, 
			initiator_id_hi, initiator_id_lo, monitor_cp_req);
	if (token_p)
		atomic_inc(&token_p->ref_count);
 
	spin_unlock_bh(&tpg_p->token_root_lock);
	return token_p;
}

int odx_rb_token_put(
	struct tpc_token_data *token_p
	)
{
	int count = 1;

	spin_lock_bh(&token_p->tpg_p->token_root_lock);

	/* not need to decrease due to it is default value */
	if (atomic_read(&token_p->ref_count) == 1) {
		spin_unlock_bh(&token_p->tpg_p->token_root_lock);
		return count;
	}

	atomic_dec(&token_p->ref_count);
	count = atomic_read(&token_p->ref_count);
	spin_unlock_bh(&token_p->tpg_p->token_root_lock);

	pr_debug("%s: p:0x%p, refcount:%d\n", __func__, token_p, count);

	return count;
}

int odx_rb_token_add(
	struct tpc_tpg_data *tpg_p,
	struct tpc_token_data *token_p
	)
{
	struct tpc_token_data *tmp_token_p = NULL;
	struct __reg_data *data = &token_p->reg_data;
	struct __reg_data *tmp_data = NULL;
	struct rb_node **p = NULL;
	struct rb_node *parent = NULL;

	if (!tpg_p || !token_p)
		return -ENODEV;

	spin_lock_bh(&tpg_p->token_root_lock);
	
	p = &tpg_p->token_root.rb_node;
	
	while (*p) {
		parent = *p;
		tmp_token_p = rb_entry(parent, struct tpc_token_data, node);
		tmp_data = &tmp_token_p->reg_data;

		if ((data->cmd_id_hi < tmp_data->cmd_id_hi)
		|| ((data->cmd_id_hi == tmp_data->cmd_id_hi) 
				&& (data->cmd_id_lo < tmp_data->cmd_id_lo))
		)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	
	pr_debug("%s: add token(0x%p) (id:0x%x)\n", __func__, token_p, 
		token_p->reg_data.list_id);

	rb_link_node(&token_p->node, parent, p);
	rb_insert_color(&token_p->node, &tpg_p->token_root);

	spin_unlock_bh(&tpg_p->token_root_lock);
	return 0;

}


struct tpc_tpg_data *odx_rb_tpg_add_and_get(
	u64 tpg_id_hi,
	u64 tpg_id_lo
	)
{
	struct rb_node **p = &tpc_tpg_root.rb_node;
	struct rb_node *parent = NULL;
	struct tpc_tpg_data *tpg_data = NULL, *tmp_tpg_data = NULL;

	tpg_data = __odx_rb_tpg_alloc(tpg_id_hi, tpg_id_lo);
	if (!tpg_data) {
		pr_err("%s: fail to alloc mem\n", __func__);
		return NULL;
	}

	spin_lock_bh(&tpc_tpg_lock);

	while (*p) {
		parent = *p;
		tmp_tpg_data = rb_entry(parent, struct tpc_tpg_data, node);

		if ((tpg_data->id_hi < tmp_tpg_data->id_hi)
		|| ((tpg_data->id_hi == tmp_tpg_data->id_hi) 
			&& (tpg_data->id_lo < tmp_tpg_data->id_lo))
		)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&tpg_data->node, parent, p);
	rb_insert_color(&tpg_data->node, &tpc_tpg_root);

	atomic_inc(&tpg_data->ref_count);
	pr_debug("%s: tpg_p:0x%p, refcount:%d\n", __func__, tpg_data, 
		atomic_read(&tpg_data->ref_count));

	spin_unlock_bh(&tpc_tpg_lock);

	return tpg_data;
}


/* tpc_tpg_lock shall be hold when to call */
struct tpc_tpg_data *odx_rb_tpg_find(
	u64 tpg_id_hi, 
	u64 tpg_id_lo
	)
{
	struct rb_node *n = tpc_tpg_root.rb_node;
	struct tpc_tpg_data *p = NULL;

	while (n) {
		p = rb_entry(n, struct tpc_tpg_data, node);

		if ((tpg_id_hi < p->id_hi)
			|| ((tpg_id_hi == p->id_hi) && (tpg_id_lo < p->id_lo))
		)
			n = n->rb_left;
		else {
			if ((tpg_id_hi == p->id_hi) && (tpg_id_lo == p->id_lo))
				return p;

			n = n->rb_right;
		}
	}
	return NULL;
}

struct tpc_tpg_data *odx_rb_tpg_get(
	u64 tpg_id_hi, 
	u64 tpg_id_lo
	)
{
	struct tpc_tpg_data *tpg_p = NULL;

	spin_lock_bh(&tpc_tpg_lock);

	tpg_p = odx_rb_tpg_find(tpg_id_hi, tpg_id_lo);
	if (tpg_p) {
		atomic_inc(&tpg_p->ref_count);
		pr_debug("%s: tpg_p:0x%p, refcount:%d\n", __func__, tpg_p, 
			atomic_read(&tpg_p->ref_count));
	}

	spin_unlock_bh(&tpc_tpg_lock);
	return tpg_p;
}

int odx_rb_tpg_put(struct tpc_tpg_data *tpg_p)
{
	int count = 1;

	spin_lock_bh(&tpc_tpg_lock);

	/* not need to decrease due to it is default value */
	if (atomic_read(&tpg_p->ref_count) == 1) {
		spin_unlock_bh(&tpc_tpg_lock);
		return count;
	}

	atomic_dec(&tpg_p->ref_count);
	count = atomic_read(&tpg_p->ref_count);
	spin_unlock_bh(&tpc_tpg_lock);

	pr_debug("%s: tpg_p:0x%p, refcount:%d\n", __func__, tpg_p, count);

	return count;
}

void odx_rb_tpg_del(
	struct tpc_tpg_data *tpg_p
	)
{
	if (!tpg_p)
		return;

	spin_lock_bh(&tpc_tpg_lock);
	pr_debug("%s: del:0x%p from rb tree\n", __func__, tpg_p);

	rb_erase(&tpg_p->node, &tpc_tpg_root);
	RB_CLEAR_NODE(&tpg_p->node);
	spin_unlock_bh(&tpc_tpg_lock);

	__odx_rb_del_tpg(tpg_p);

	pr_debug("%s: free:0x%p\n", __func__, tpg_p);
	kmem_cache_free(odx_tpg_data_cache, tpg_p);

}

struct tpc_cmd_data *odx_rb_cmd_add_and_get(
	struct tpc_tpg_data *tpg_p, 
	struct __reg_data *reg_data
	)
{
	struct tpc_cmd_data *data = NULL, *tmp_data = NULL;
	struct rb_node **p = NULL;
	struct rb_node *parent = NULL;

	if (!tpg_p)
		return NULL;
	
	data = __odx_rb_cmd_alloc(tpg_p, reg_data);
	if (!data)
		return NULL;

	spin_lock_bh(&tpg_p->cmd_root_lock);

	p = &tpg_p->cmd_root.rb_node;

	while (*p) {
		parent = *p;
		tmp_data = rb_entry(parent, struct tpc_cmd_data, node);

		if ((data->reg_data.cmd_id_hi < tmp_data->reg_data.cmd_id_hi)
		|| ((data->reg_data.cmd_id_hi == tmp_data->reg_data.cmd_id_hi) 
			&& (data->reg_data.cmd_id_lo < tmp_data->reg_data.cmd_id_lo))
		)
			p = &(*p)->rb_left;
		else 
			p = &(*p)->rb_right;
	}

	rb_link_node(&data->node, parent, p);
	rb_insert_color(&data->node, &tpg_p->cmd_root);

	atomic_inc(&data->ref_count);
	pr_debug("%s: cmd:0x%p, refcount:%d\n", __func__, data, 
		atomic_read(&data->ref_count));

	spin_unlock_bh(&tpg_p->cmd_root_lock);
	return data;
}


/* cmd_root_lock shall be hold when to call */
struct tpc_cmd_data *odx_rb_cmd_find(
	struct tpc_tpg_data *tpg_p,
	struct __reg_data *reg_data, 
	bool skip_iid, 
	bool skip_sac
	)
{
	struct rb_root root = tpg_p->cmd_root;
	struct rb_node *n = root.rb_node;
	struct tpc_cmd_data *data = NULL;
	struct __reg_data *tmp_reg_data;

	while (n) {
		data = rb_entry(n, struct tpc_cmd_data, node);
		tmp_reg_data = &data->reg_data;

		if ((reg_data->cmd_id_hi < tmp_reg_data->cmd_id_hi)
		|| ((reg_data->cmd_id_hi == tmp_reg_data->cmd_id_hi) 
			&& (reg_data->cmd_id_lo < tmp_reg_data->cmd_id_lo))
		)
			n = n->rb_left;
		else {
			pr_debug("passed type:%d\n", reg_data->cmd_type);
			pr_debug("passed cmd_id_hi:0x%llx\n", reg_data->cmd_id_hi);
			pr_debug("passed cmd_id_lo:0x%llx\n", reg_data->cmd_id_lo);
			pr_debug("checked cmd_id_hi:0x%llx\n", tmp_reg_data->cmd_id_hi);
			pr_debug("checked cmd_id_lo:0x%llx\n", tmp_reg_data->cmd_id_lo);
			pr_debug("checked type:%d\n", tmp_reg_data->cmd_type);

			if ((reg_data->cmd_id_hi == tmp_reg_data->cmd_id_hi)
			&& (reg_data->cmd_id_lo == tmp_reg_data->cmd_id_lo)
			/* we want same cmd type ... */
			&& (reg_data->cmd_type == tmp_reg_data->cmd_type)
			)
			{
				/* if check sac but they are different ... */
				if (!skip_sac && (reg_data->sac != tmp_reg_data->sac))
					goto next_node;

				/* if check initiator id but they are different ...*/
				if (!skip_iid 
				&& ((reg_data->initiator_id_hi != tmp_reg_data->initiator_id_hi)
					|| (reg_data->initiator_id_lo != tmp_reg_data->initiator_id_lo)
				))
					goto next_node;

				pr_debug("%s: found tc (0x%p)\n", __func__, data);
				return data;
			}
next_node:
			n = n->rb_right;
		}
	}
	return NULL;

}

int odx_rb_cmd_put(
	struct tpc_cmd_data *tc_p
	)
{
	int count = 1;

	spin_lock_bh(&tc_p->tpg_p->cmd_root_lock);

	/* not need to decrease due to it is default value */
	if (atomic_read(&tc_p->ref_count) == 1) {
		spin_unlock_bh(&tc_p->tpg_p->cmd_root_lock);
		return count;
	}

	atomic_dec(&tc_p->ref_count);
	count = atomic_read(&tc_p->ref_count);
	spin_unlock_bh(&tc_p->tpg_p->cmd_root_lock);

	pr_debug("%s: p:0x%p, refcount:%d\n", __func__, tc_p, count);
	return count;

}

struct tpc_cmd_data *odx_rb_cmd_get(
	struct tpc_tpg_data *tpg_p, 
	struct __reg_data *reg_data,
	bool skip_iid, 
	bool skip_sac
	)
{
	struct tpc_cmd_data *p;

	if (!tpg_p)
		return NULL;

	spin_lock_bh(&tpg_p->cmd_root_lock);

	p = odx_rb_cmd_find(tpg_p, reg_data, skip_iid, skip_sac);
	if (p)
		atomic_inc(&p->ref_count);

	spin_unlock_bh(&tpg_p->cmd_root_lock);

	return p;
}

void odx_rb_cmd_del(
	struct tpc_tpg_data *tpg_p,
	struct tpc_cmd_data *tc_p
	)
{
	if (!tpg_p || !tc_p)
		return;

	spin_lock_bh(&tpg_p->cmd_root_lock);

	pr_debug("%s: del:0x%p from rb tree\n", __func__, tc_p);
	rb_erase(&tc_p->node, &tpg_p->cmd_root);
	RB_CLEAR_NODE(&tc_p->node);

	spin_unlock_bh(&tpg_p->cmd_root_lock);
}

void odx_rb_cmd_free(
	struct tpc_cmd_data *tc_p
	)
{
	kmem_cache_free(odx_cmd_data_cache, tc_p);
}

static bool __odx_rb_find_conflict_lba_in_token(
	struct tpc_token_data *token_p,
	sector_t lba,
	u32 nr_blks
	)
{
	struct list_head *br_list = &token_p->br_list;
	struct blk_range_data *br = NULL;
	bool invalidate = false;

	spin_lock_bh(&token_p->br_list_lock);

	/* if found one of br in token is overlapped by [lba, range], we will
	 * invalidate this token
	 */
	list_for_each_entry(br, br_list, br_node) {
		if (br->curr_status == R_STATUS_TRUNCATE_USED)
			continue;

		if (!invalidate){
			if (lba >= br->lba && lba <= (br->lba + br->nr_blks - 1)) {
				if (br->curr_status == R_STATUS_NOT_USED)
					br->next_status = br->curr_status = R_STATUS_TRUNCATE_USED;
				else {
					WARN_ON(br->curr_status != R_STATUS_TRANSFER_USED);
					br->next_status = R_STATUS_TRUNCATE_USED;
				}
				invalidate = true;
			}
		} else {
			/* treat other br to be invalidated */
			if (br->curr_status == R_STATUS_TRANSFER_USED)
				br->next_status = R_STATUS_TRUNCATE_USED;
			else
				br->next_status = br->curr_status = R_STATUS_TRUNCATE_USED;
		}
	}

	spin_unlock_bh(&token_p->br_list_lock);

	return invalidate;

}

int odx_rb_parse_conflict_token_range(
	struct tpc_tpg_data *tpg_p, 
	struct __dev_info *dev_info,
	struct blk_dev_range_desc *blk_range_desc,
	u16 desc_idx,
	u8 cdb0,
	u8 cdb1
	)
{
	struct rb_node *token_n = NULL, *next_token_n = NULL;
	struct tpc_token_data *token_p = NULL;
	struct __reg_data *reg_d = NULL;
	sector_t lba = get_unaligned_be64(&blk_range_desc->lba[0]);
	u32 nr_blks = get_unaligned_be32(&blk_range_desc->nr_blks[0]);
	bool invalidate_token;
	int ret;
	RC rc;

	spin_lock_bh(&tpg_p->token_root_lock);

	for (token_n = rb_first(&tpg_p->token_root); 
			token_n; token_n = rb_next(token_n)) 
	{
		token_p = rb_entry(token_n, struct tpc_token_data, node);
		reg_d = &token_p->reg_data; 

		/* discard token where the device is same as passing command */
		if (memcmp(&dev_info->naa[0], &reg_d->dev_info.naa[0], NAA_LEN))
			continue;

		ret = __odx_is_token_invalid(token_p, &rc);
		if (ret != 0) {
			pr_debug("warning, token (list id:0x%x, sac:0x%x) "
				"was NOT alive during to parse conflict "
				"lba range by cmd (cdb[0]:0x%x, cdb[1]:0x%x, "
				"desc index:%d). status:%d\n", reg_d->list_id, 
				reg_d->sac, cdb0, cdb1, desc_idx, rc);
			continue;
		}

		atomic_inc(&token_p->ref_count);

		invalidate_token = __odx_rb_find_conflict_lba_in_token(
					token_p, lba, nr_blks);

		if (invalidate_token) {
			pr_warn("warning, cmd range (cdb[0]:0x%x, cdb[1]:0x%x, "
				"desc idx:%d, lba:0x%llx, nr_blks:0x%x) "
				"conflicts with token (list id:0x%x, "
				"op_sac:0x%x). to cancel token\n", 
				cdb0, cdb1, desc_idx, (unsigned long long)lba, 
				nr_blks, reg_d->list_id, reg_d->sac);

			__odx_cmpxchg_token_status(token_p, O_TOKEN_ALIVE, O_TOKEN_CANCELLED);
		}

		
		if (atomic_read(&token_p->ref_count) != 1)
			atomic_dec(&token_p->ref_count);


	}

	spin_unlock_bh(&tpg_p->token_root_lock);

	return 0;

}


