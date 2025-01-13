/*
 * Copyright (C) 2016 Netronome Systems, Inc.
 *
 * This software is dual licensed under the GNU General License Version 2,
 * June 1991 as shown in the file COPYING in the top-level directory of this
 * source tree or the BSD 2-Clause License provided below.  You have the
 * option to license this software under the complete terms of either license.
 *
 * The BSD 2-Clause License:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      1. Redistributions of source code must retain the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer.
 *
 *      2. Redistributions in binary form must reproduce the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer in the documentation and/or other materials
 *         provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * nfp_net_offload.c
 * Netronome network device driver: TC offload functions for PF and VF
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/list.h>

#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_mirred.h>

#include "main.h"
#include "../nfp_net_ctrl.h"
#include "../nfp_net.h"

void nfp_net_filter_stats_timer(unsigned long data)
{
	struct nfp_net *nn = (void *)data;
	struct nfp_net_bpf_priv *priv;
	struct nfp_stat_pair latest;

	priv = nn->app_priv;

	spin_lock_bh(&priv->rx_filter_lock);

	if (nn->dp.ctrl & NFP_NET_CFG_CTRL_BPF)
		mod_timer(&priv->rx_filter_stats_timer,
			  jiffies + NFP_NET_STAT_POLL_IVL);

	spin_unlock_bh(&priv->rx_filter_lock);

	latest.pkts = nn_readq(nn, NFP_NET_CFG_STATS_APP1_FRAMES);
	latest.bytes = nn_readq(nn, NFP_NET_CFG_STATS_APP1_BYTES);

	if (latest.pkts != priv->rx_filter.pkts)
		priv->rx_filter_change = jiffies;

	priv->rx_filter = latest;
}

static void nfp_net_bpf_stats_reset(struct nfp_net *nn)
{
	struct nfp_net_bpf_priv *priv = nn->app_priv;

	priv->rx_filter.pkts = nn_readq(nn, NFP_NET_CFG_STATS_APP1_FRAMES);
	priv->rx_filter.bytes = nn_readq(nn, NFP_NET_CFG_STATS_APP1_BYTES);
	priv->rx_filter_prev = priv->rx_filter;
	priv->rx_filter_change = jiffies;
}

static int
nfp_net_bpf_stats_update(struct nfp_net *nn, struct tc_cls_bpf_offload *cls_bpf)
{
	struct nfp_net_bpf_priv *priv = nn->app_priv;
	u64 bytes, pkts;

	pkts = priv->rx_filter.pkts - priv->rx_filter_prev.pkts;
	bytes = priv->rx_filter.bytes - priv->rx_filter_prev.bytes;
	bytes -= pkts * ETH_HLEN;

	priv->rx_filter_prev = priv->rx_filter;

	tcf_exts_stats_update(cls_bpf->exts,
			      bytes, pkts, priv->rx_filter_change);

	return 0;
}

static int
nfp_net_bpf_get_act(struct nfp_net *nn, struct tc_cls_bpf_offload *cls_bpf)
{
	const struct tc_action *a;
	LIST_HEAD(actions);

	if (!cls_bpf->exts)
		return NN_ACT_XDP;

	/* TC direct action */
	if (cls_bpf->exts_integrated) {
		if (!tcf_exts_has_actions(cls_bpf->exts))
			return NN_ACT_DIRECT;

		return -EOPNOTSUPP;
	}

	/* TC legacy mode */
	if (!tcf_exts_has_one_action(cls_bpf->exts))
		return -EOPNOTSUPP;

	tcf_exts_to_list(cls_bpf->exts, &actions);
	list_for_each_entry(a, &actions, list) {
		if (is_tcf_gact_shot(a))
			return NN_ACT_TC_DROP;

		if (is_tcf_mirred_egress_redirect(a) &&
		    tcf_mirred_ifindex(a) == nn->dp.netdev->ifindex)
			return NN_ACT_TC_REDIR;
	}

	return -EOPNOTSUPP;
}

static int
nfp_net_bpf_offload_prepare(struct nfp_net *nn,
			    struct tc_cls_bpf_offload *cls_bpf,
			    struct nfp_bpf_result *res,
			    void **code, dma_addr_t *dma_addr, u16 max_instr)
{
	unsigned int code_sz = max_instr * sizeof(u64);
	enum nfp_bpf_action_type act;
	u16 start_off, done_off;
	unsigned int max_mtu;
	int ret;

	if (!IS_ENABLED(CONFIG_BPF_SYSCALL))
		return -EOPNOTSUPP;

	ret = nfp_net_bpf_get_act(nn, cls_bpf);
	if (ret < 0)
		return ret;
	act = ret;

	max_mtu = nn_readb(nn, NFP_NET_CFG_BPF_INL_MTU) * 64 - 32;
	if (max_mtu < nn->dp.netdev->mtu) {
		nn_info(nn, "BPF offload not supported with MTU larger than HW packet split boundary\n");
		return -EOPNOTSUPP;
	}

	start_off = nn_readw(nn, NFP_NET_CFG_BPF_START);
	done_off = nn_readw(nn, NFP_NET_CFG_BPF_DONE);

	*code = dma_zalloc_coherent(nn->dp.dev, code_sz, dma_addr, GFP_KERNEL);
	if (!*code)
		return -ENOMEM;

	ret = nfp_bpf_jit(cls_bpf->prog, *code, act, start_off, done_off,
			  max_instr, res);
	if (ret)
		goto out;

	return 0;

out:
	dma_free_coherent(nn->dp.dev, code_sz, *code, *dma_addr);
	return ret;
}

static void
nfp_net_bpf_load_and_start(struct nfp_net *nn, u32 tc_flags,
			   void *code, dma_addr_t dma_addr,
			   unsigned int code_sz, unsigned int n_instr,
			   bool dense_mode)
{
	struct nfp_net_bpf_priv *priv = nn->app_priv;
	u64 bpf_addr = dma_addr;
	int err;

	nn->dp.bpf_offload_skip_sw = !!(tc_flags & TCA_CLS_FLAGS_SKIP_SW);

	if (dense_mode)
		bpf_addr |= NFP_NET_CFG_BPF_CFG_8CTX;

static int
nfp_bpf_map_update_entry(struct bpf_offloaded_map *offmap,
			 void *key, void *value, u64 flags)
{
	nfp_map_bpf_byte_swap(offmap->dev_priv, value);
	nfp_map_bpf_byte_swap_record(offmap->dev_priv, value);
	return nfp_bpf_ctrl_update_entry(offmap, key, value, flags);
}

static int
nfp_bpf_map_get_next_key(struct bpf_offloaded_map *offmap,
			 void *key, void *next_key)
{
	if (!key)
		return nfp_bpf_ctrl_getfirst_entry(offmap, next_key);
	return nfp_bpf_ctrl_getnext_entry(offmap, key, next_key);
}

static int
nfp_bpf_map_delete_elem(struct bpf_offloaded_map *offmap, void *key)
{
	if (offmap->map.map_type == BPF_MAP_TYPE_ARRAY)
		return -EINVAL;
	return nfp_bpf_ctrl_del_entry(offmap, key);
}

static const struct bpf_map_dev_ops nfp_bpf_map_ops = {
	.map_get_next_key	= nfp_bpf_map_get_next_key,
	.map_lookup_elem	= nfp_bpf_map_lookup_entry,
	.map_update_elem	= nfp_bpf_map_update_entry,
	.map_delete_elem	= nfp_bpf_map_delete_elem,
};

static int
nfp_bpf_map_alloc(struct nfp_app_bpf *bpf, struct bpf_offloaded_map *offmap)
{
	struct nfp_bpf_map *nfp_map;
	unsigned int use_map_size;
	long long int res;

	if (!bpf->maps.types)
		return -EOPNOTSUPP;

	if (offmap->map.map_flags ||
	    offmap->map.numa_node != NUMA_NO_NODE) {
		pr_info("map flags are not supported\n");
		return -EINVAL;
	}

	if (!(bpf->maps.types & 1 << offmap->map.map_type)) {
		pr_info("map type not supported\n");
		return -EOPNOTSUPP;
	}
	if (bpf->maps.max_maps == bpf->maps_in_use) {
		pr_info("too many maps for a device\n");
		return -ENOMEM;
	}
	if (bpf->maps.max_elems - bpf->map_elems_in_use <
	    offmap->map.max_entries) {
		pr_info("map with too many elements: %u, left: %u\n",
			offmap->map.max_entries,
			bpf->maps.max_elems - bpf->map_elems_in_use);
		return -ENOMEM;
	}

	if (round_up(offmap->map.key_size, 8) +
	    round_up(offmap->map.value_size, 8) > bpf->maps.max_elem_sz) {
		pr_info("map elements too large: %u, FW max element size (key+value): %u\n",
			round_up(offmap->map.key_size, 8) +
			round_up(offmap->map.value_size, 8),
			bpf->maps.max_elem_sz);
		return -ENOMEM;
	}
	if (offmap->map.key_size > bpf->maps.max_key_sz) {
		pr_info("map key size %u, FW max is %u\n",
			offmap->map.key_size, bpf->maps.max_key_sz);
		return -ENOMEM;
	}
	if (offmap->map.value_size > bpf->maps.max_val_sz) {
		pr_info("map value size %u, FW max is %u\n",
			offmap->map.value_size, bpf->maps.max_val_sz);
		return -ENOMEM;
	}

	use_map_size = DIV_ROUND_UP(offmap->map.value_size, 4) *
		       FIELD_SIZEOF(struct nfp_bpf_map, use_map[0]);

	nfp_map = kzalloc(sizeof(*nfp_map) + use_map_size, GFP_USER);
	if (!nfp_map)
		return -ENOMEM;

	offmap->dev_priv = nfp_map;
	nfp_map->offmap = offmap;
	nfp_map->bpf = bpf;
	spin_lock_init(&nfp_map->cache_lock);

	res = nfp_bpf_ctrl_alloc_map(bpf, &offmap->map);
	if (res < 0) {
		kfree(nfp_map);
		return res;
	}

	nfp_map->tid = res;
	offmap->dev_ops = &nfp_bpf_map_ops;
	bpf->maps_in_use++;
	bpf->map_elems_in_use += offmap->map.max_entries;
	list_add_tail(&nfp_map->l, &bpf->map_list);

	return 0;
}

static int
nfp_bpf_map_free(struct nfp_app_bpf *bpf, struct bpf_offloaded_map *offmap)
{
	struct nfp_bpf_map *nfp_map = offmap->dev_priv;

	nfp_bpf_ctrl_free_map(bpf, nfp_map);
	dev_consume_skb_any(nfp_map->cache);
	WARN_ON_ONCE(nfp_map->cache_blockers);
	list_del_init(&nfp_map->l);
	bpf->map_elems_in_use -= offmap->map.max_entries;
	bpf->maps_in_use--;
	kfree(nfp_map);

	return 0;
}

int nfp_ndo_bpf(struct nfp_app *app, struct nfp_net *nn, struct netdev_bpf *bpf)
{
	switch (bpf->command) {
	case BPF_OFFLOAD_MAP_ALLOC:
		return nfp_bpf_map_alloc(app->priv, bpf->offmap);
	case BPF_OFFLOAD_MAP_FREE:
		return nfp_bpf_map_free(app->priv, bpf->offmap);
	default:
		return -EINVAL;
	}
}

static unsigned long
nfp_bpf_perf_event_copy(void *dst, const void *src,
			unsigned long off, unsigned long len)
{
	memcpy(dst, src + off, len);
	return 0;
}

int nfp_bpf_event_output(struct nfp_app_bpf *bpf, const void *data,
			 unsigned int len)
{
	struct cmsg_bpf_event *cbe = (void *)data;
	struct nfp_bpf_neutral_map *record;
	u32 pkt_size, data_size, map_id;
	u64 map_id_full;

	if (len < sizeof(struct cmsg_bpf_event))
		return -EINVAL;

	pkt_size = be32_to_cpu(cbe->pkt_size);
	data_size = be32_to_cpu(cbe->data_size);
	map_id_full = be64_to_cpu(cbe->map_ptr);
	map_id = map_id_full;

	if (size_add(pkt_size, data_size) > INT_MAX ||
	    len < sizeof(struct cmsg_bpf_event) + pkt_size + data_size)
		return -EINVAL;
	if (cbe->hdr.ver != NFP_CCM_ABI_VERSION)
		return -EINVAL;

	rcu_read_lock();
	record = rhashtable_lookup_fast(&bpf->maps_neutral, &map_id,
					nfp_bpf_maps_neutral_params);
	if (!record || map_id_full > U32_MAX) {
		rcu_read_unlock();
		cmsg_warn(bpf, "perf event: map id %lld (0x%llx) not recognized, dropping event\n",
			  map_id_full, map_id_full);
		return -EINVAL;
	}

	bpf_event_output(record->ptr, be32_to_cpu(cbe->cpu_id),
			 &cbe->data[round_up(pkt_size, 4)], data_size,
			 cbe->data, pkt_size, nfp_bpf_perf_event_copy);
	rcu_read_unlock();

	return 0;
}

bool nfp_bpf_offload_check_mtu(struct nfp_net *nn, struct bpf_prog *prog,
			       unsigned int mtu)
{
	unsigned int fw_mtu, pkt_off;

	fw_mtu = nn_readb(nn, NFP_NET_CFG_BPF_INL_MTU) * 64 - 32;
	pkt_off = min(prog->aux->max_pkt_offset, mtu);

	return fw_mtu < pkt_off;
}

static int
nfp_net_bpf_load(struct nfp_net *nn, struct bpf_prog *prog,
		 struct netlink_ext_ack *extack)
{
	struct nfp_prog *nfp_prog = prog->aux->offload->dev_priv;
	unsigned int max_stack, max_prog_len;
	dma_addr_t dma_addr;
	void *img;
	int err;

	if (nfp_bpf_offload_check_mtu(nn, prog, nn->dp.netdev->mtu)) {
		NL_SET_ERR_MSG_MOD(extack, "BPF offload not supported with potential packet access beyond HW packet split boundary");
		return -EOPNOTSUPP;
	}

	max_stack = nn_readb(nn, NFP_NET_CFG_BPF_STACK_SZ) * 64;
	if (nfp_prog->stack_size > max_stack) {
		NL_SET_ERR_MSG_MOD(extack, "stack too large");
		return -EOPNOTSUPP;
	}

	max_prog_len = nn_readw(nn, NFP_NET_CFG_BPF_MAX_LEN);
	if (nfp_prog->prog_len > max_prog_len) {
		NL_SET_ERR_MSG_MOD(extack, "program too long");
		return -EOPNOTSUPP;
	}

	img = nfp_bpf_relo_for_vnic(nfp_prog, nn->app_priv);
	if (IS_ERR(img))
		return PTR_ERR(img);

	dma_addr = dma_map_single(nn->dp.dev, img,
				  nfp_prog->prog_len * sizeof(u64),
				  DMA_TO_DEVICE);
	if (dma_mapping_error(nn->dp.dev, dma_addr)) {
		kfree(img);
		return -ENOMEM;
	}

	nn_writew(nn, NFP_NET_CFG_BPF_SIZE, nfp_prog->prog_len);
	nn_writeq(nn, NFP_NET_CFG_BPF_ADDR, dma_addr);

	/* Load up the JITed code */
	err = nfp_net_reconfig(nn, NFP_NET_CFG_UPDATE_BPF);
	if (err)
		nn_err(nn, "FW command error while loading BPF: %d\n", err);

	/* Enable passing packets through BPF function */
	nn->dp.ctrl |= NFP_NET_CFG_CTRL_BPF;
	nn_writel(nn, NFP_NET_CFG_CTRL, nn->dp.ctrl);
	err = nfp_net_reconfig(nn, NFP_NET_CFG_UPDATE_GEN);
	if (err)
		nn_err(nn, "FW command error while enabling BPF: %d\n", err);

	dma_free_coherent(nn->dp.dev, code_sz, code, dma_addr);

	nfp_net_bpf_stats_reset(nn);
	mod_timer(&priv->rx_filter_stats_timer,
		  jiffies + NFP_NET_STAT_POLL_IVL);
}

static int nfp_net_bpf_stop(struct nfp_net *nn)
{
	struct nfp_net_bpf_priv *priv = nn->app_priv;

	if (!(nn->dp.ctrl & NFP_NET_CFG_CTRL_BPF))
		return 0;

	spin_lock_bh(&priv->rx_filter_lock);
	nn->dp.ctrl &= ~NFP_NET_CFG_CTRL_BPF;
	spin_unlock_bh(&priv->rx_filter_lock);
	nn_writel(nn, NFP_NET_CFG_CTRL, nn->dp.ctrl);

	del_timer_sync(&priv->rx_filter_stats_timer);
	nn->dp.bpf_offload_skip_sw = 0;

	return nfp_net_reconfig(nn, NFP_NET_CFG_UPDATE_GEN);
}

int nfp_net_bpf_offload(struct nfp_net *nn, struct tc_cls_bpf_offload *cls_bpf)
{
	struct nfp_bpf_result res;
	dma_addr_t dma_addr;
	u16 max_instr;
	void *code;
	int err;

	max_instr = nn_readw(nn, NFP_NET_CFG_BPF_MAX_LEN);

	switch (cls_bpf->command) {
	case TC_CLSBPF_REPLACE:
		/* There is nothing stopping us from implementing seamless
		 * replace but the simple method of loading I adopted in
		 * the firmware does not handle atomic replace (i.e. we have to
		 * stop the BPF offload and re-enable it).  Leaking-in a few
		 * frames which didn't have BPF applied in the hardware should
		 * be fine if software fallback is available, though.
		 */
		if (nn->dp.bpf_offload_skip_sw)
			return -EBUSY;

		err = nfp_net_bpf_offload_prepare(nn, cls_bpf, &res, &code,
						  &dma_addr, max_instr);
		if (err)
			return err;

		nfp_net_bpf_stop(nn);
		nfp_net_bpf_load_and_start(nn, cls_bpf->gen_flags, code,
					   dma_addr, max_instr * sizeof(u64),
					   res.n_instr, res.dense_mode);
		return 0;

	case TC_CLSBPF_ADD:
		if (nn->dp.ctrl & NFP_NET_CFG_CTRL_BPF)
			return -EBUSY;

		err = nfp_net_bpf_offload_prepare(nn, cls_bpf, &res, &code,
						  &dma_addr, max_instr);
		if (err)
			return err;

		nfp_net_bpf_load_and_start(nn, cls_bpf->gen_flags, code,
					   dma_addr, max_instr * sizeof(u64),
					   res.n_instr, res.dense_mode);
		return 0;

	case TC_CLSBPF_DESTROY:
		return nfp_net_bpf_stop(nn);

	case TC_CLSBPF_STATS:
		return nfp_net_bpf_stats_update(nn, cls_bpf);

	default:
		return -EOPNOTSUPP;
	}
}
