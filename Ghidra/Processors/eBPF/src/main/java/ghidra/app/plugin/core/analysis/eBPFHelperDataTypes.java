/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.io.Closeable;
import java.io.IOException;

import ghidra.app.plugin.core.analysis.TransientProgramProperties.SCOPE;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.importer.MessageLog;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class eBPFHelperDataTypes implements Closeable {

	private static final String EBPF_DATATYPE_MGR_PROPERTY_KEY = "eBPFDataTypes";

	/**
	 * Ordered list of BPF helper functions.  Array index corresponds to helper ID.
	 * A null may be substituted for a missing/unknown function definition. 
	 * 
	 * References:
	 *   https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h
	 *   https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
	 */
	//@formatter:off
	private static final String[] bpfHelperSignatures = new String[] {
		// Helper IDs: 0..9
		"void bpf_unspec()",
		"void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)",
		"int bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)",
		"int bpf_map_delete_elem(struct bpf_map *map, const void *key)",
		"int bpf_probe_read(void *dst, u32 size, const void *src)",
		"u64 bpf_ktime_get_ns(void)",
		"int bpf_trace_printk(const char *fmt, u32 fmt_size, ...)",
		"u32 bpf_get_prandom_u32(void)",
		"u32 bpf_get_smp_processor_id(void)",
		"int bpf_skb_store_bytes(struct sk_buff *skb, u32 offset, const void *from, u32 len, u64 flags)",
		
		// Helper IDs: 10..19
		"int bpf_l3_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 size)",
		"int bpf_l4_csum_replace(struct sk_buff *skb, u32 offset, u64 from, u64 to, u64 flags)",
		"int bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, u32 index)",
		"int bpf_clone_redirect(struct sk_buff *skb, u32 ifindex, u64 flags)",
		"u64 bpf_get_current_pid_tgid(void)",
		"u64 bpf_get_current_uid_gid(void)",
		"int bpf_get_current_comm(char *buf, u32 size_of_buf)",
		"u32 bpf_get_cgroup_classid(struct sk_buff *skb)",
		"int bpf_skb_vlan_push(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)",
		"int bpf_skb_vlan_pop(struct sk_buff *skb)",
		
		// Helper IDs: 20..29
		"int bpf_skb_get_tunnel_key(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags)",
		"int bpf_skb_set_tunnel_key(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags)",
		"u64 bpf_perf_event_read(struct bpf_map *map, u64 flags)",
		"int bpf_redirect(u32 ifindex, u64 flags)",
		"u32 bpf_get_route_realm(struct sk_buff *skb)",
		"int bpf_perf_event_output(struct pt_reg *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)",
		"int bpf_skb_load_bytes(const struct sk_buff *skb, u32 offset, void *to, u32 len)",
		"int bpf_get_stackid(struct pt_reg *ctx, struct bpf_map *map, u64 flags)",
		"s64 bpf_csum_diff(__be32 *from, u32 from_size, __be32 *to, u32 to_size, __wsum seed)",
		"int bpf_skb_get_tunnel_opt(struct sk_buff *skb, u8 *opt, u32 size)",
		
		// Helper IDs: 30..39
		"int bpf_skb_set_tunnel_opt(struct sk_buff *skb, u8 *opt, u32 size)",
		"int bpf_skb_change_proto(struct sk_buff *skb, __be16 proto, u64 flags)",
		"int bpf_skb_change_type(struct sk_buff *skb, u32 type)",
		"int bpf_skb_under_cgroup(struct sk_buff *skb, struct bpf_map *map, u32 index)",
		"u32 bpf_get_hash_recalc(struct sk_buff *skb)",
		"u64 bpf_get_current_task(void)",
		"int bpf_probe_write_user(void *dst, const void *src, u32 len)",
		"int bpf_current_task_under_cgroup(struct bpf_map *map, u32 index)",
		"int bpf_skb_change_tail(struct sk_buff *skb, u32 len, u64 flags)",
		"int bpf_skb_pull_data(struct sk_buff *skb, u32 len)",
		
		// Helper IDs: 40..49
		"s64 bpf_csum_update(struct sk_buff *skb, __wsum csum)",
		"void bpf_set_hash_invalid(struct sk_buff *skb)",
		"int bpf_get_numa_node_id(void)",
		"int bpf_skb_change_head(struct sk_buff *skb, u32 len, u64 flags)",
		"int bpf_xdp_adjust_head(struct xdp_buff *xdp_md, int delta)",
		"int bpf_probe_read_str(void *dst, u32 size, const void *unsafe_ptr)",
		// NOTE: bpf_get_socket_cookie function is overloaded based upon program type so
		// we define the argument as a void pointer within the generic function definition
		//   u64 bpf_get_socket_cookie(struct sk_buff *skb)
		//   u64 bpf_get_socket_cookie(struct bpf_sock_addr *ctx)
		//   u64 bpf_get_socket_cookie(struct bpf_sock_ops *ctx)
		//   u64 bpf_get_socket_cookie(struct sock *sk)
		"u64 bpf_get_socket_cookie(void *ctx)",
		"u32 bpf_get_socket_uid(struct sk_buff *skb)",
		"int bpf_set_hash(struct sk_buff *skb, u32 hash)",
		"int bpf_setsockopt(void *bpf_socket, int level, int optname, void *optval, int optlen)",
		
		// Helper IDs: 50..59
		"int bpf_skb_adjust_room(struct sk_buff *skb, s32 len_diff, u32 mode, u64 flags)",
		"int bpf_redirect_map(struct bpf_map *map, u32 key, u64 flags)",
		"int bpf_sk_redirect_map(struct sk_buff *skb, struct bpf_map *map, u32 key, u64 flags)",
		"int bpf_sock_map_update(struct bpf_sock_ops *skops, struct bpf_map *map, void *key, u64 flags)",
		"int bpf_xdp_adjust_meta(struct xdp_buff *xdp_md, int delta)",
		"int bpf_perf_event_read_value(struct bpf_map *map, u64 flags, struct bpf_perf_event_value *buf, u32 buf_size)",
		"int bpf_perf_prog_read_value(struct bpf_perf_event_data *ctx, struct bpf_perf_event_value *buf, u32 buf_size)",
		"int bpf_getsockopt(void *bpf_socket, int level, int optname, void *optval, int optlen)",
		"int bpf_override_return(struct pt_regs *regs, u64 rc)",
		"int bpf_sock_ops_cb_flags_set(struct bpf_sock_ops *bpf_sock, int argval)",
		
		// Helper IDs: 60..69
		"int bpf_msg_redirect_map(struct sk_msg_buff *msg, struct bpf_map *map, u32 key, u64 flags)",
		"int bpf_msg_apply_bytes(struct sk_msg_buff *msg, u32 bytes)",
		"long bpf_msg_cork_bytes(struct sk_msg_buff *msg, u32 bytes)",
		"long bpf_msg_pull_data(struct sk_msg_buff *msg, u32 start, u32 end, u64 flags)",
		"long bpf_bind(struct bpf_sock_addr *ctx, struct sockaddr *addr, int addr_len)",
		"long bpf_xdp_adjust_tail(struct xdp_buff *xdp_md, int delta)",
		"long bpf_skb_get_xfrm_state(struct sk_buff *skb, u32 index, struct bpf_xfrm_state *xfrm_state, u32 size, u64 flags)",
		"long bpf_get_stack(void *ctx, void *buf, u32 size, u64 flags)",
		"long bpf_skb_load_bytes_relative(const void *skb, u32 offset, void *to, u32 len, u32 start_header)",
		"long bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, u32 flags)",
		
		// Helper IDs: 70..79
		"long bpf_sock_hash_update(struct bpf_sock_ops *skops, struct bpf_map *map, void *key, u64 flags)",
		"long bpf_msg_redirect_hash(struct sk_msg_buff *msg, struct bpf_map *map, void *key, u64 flags)",
		"long bpf_sk_redirect_hash(struct sk_buff *skb, struct bpf_map *map, void *key, u64 flags)",
		"long bpf_lwt_push_encap(struct sk_buff *skb, u32 type, void *hdr, u32 len)",
		"long bpf_lwt_seg6_store_bytes(struct sk_buff *skb, u32 offset, const void *from, u32 len)",
		"long bpf_lwt_seg6_adjust_srh(struct sk_buff *skb, u32 offset, s32 delta)",
		"long bpf_lwt_seg6_action(struct sk_buff *skb, u32 action, void *param, u32 param_len)",
		"long bpf_rc_repeat(void *ctx)",
		"long bpf_rc_keydown(void *ctx, u32 protocol, u64 scancode, u32 toggle)",
		"u64 bpf_skb_cgroup_id(struct sk_buff *skb)",
		
		// Helper IDs: 80..89
		"u64 bpf_get_current_cgroup_id(void)",
		"void *bpf_get_local_storage(void *map, u64 flags)",
		"long bpf_sk_select_reuseport(struct sk_reuseport_md *reuse, struct bpf_map *map, void *key, u64 flags)",
		"u64 bpf_skb_ancestor_cgroup_id(struct sk_buff *skb, int ancestor_level)",
		"struct bpf_sock *bpf_sk_lookup_tcp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)",
		"struct bpf_sock *bpf_sk_lookup_udp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)",
		"long bpf_sk_release(void *sock)",
		"long bpf_map_push_elem(struct bpf_map *map, const void *value, u64 flags)",
		"long bpf_map_pop_elem(struct bpf_map *map, void *value)",
		"long bpf_map_peek_elem(struct bpf_map *map, void *value)",
		
		// Helper IDs: 90..99
		"long bpf_msg_push_data(struct sk_msg_buff *msg, u32 start, u32 len, u64 flags)",
		"long bpf_msg_pop_data(struct sk_msg_buff *msg, u32 start, u32 len, u64 flags)",
		"long bpf_rc_pointer_rel(void *ctx, s32 rel_x, s32 rel_y)",
		"long bpf_spin_lock(struct bpf_spin_lock *lock)",
		"long bpf_spin_unlock(struct bpf_spin_lock *lock)",
		"struct bpf_sock *bpf_sk_fullsock(struct bpf_sock *sk)",
		"struct bpf_tcp_sock *bpf_tcp_sock(struct bpf_sock *sk)",
		"long bpf_skb_ecn_set_ce(struct sk_buff *skb)",
		"struct bpf_sock *bpf_get_listener_sock(struct bpf_sock *sk)",
		"struct bpf_sock *bpf_skc_lookup_tcp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)",
		
		// Helper IDs: 100..109
		"long bpf_tcp_check_syncookie(void *sk, void *iph, u32 iph_len, struct tcphdr *th, u32 th_len)",
		"long bpf_sysctl_get_name(struct bpf_sysctl *ctx, char *buf, size_t buf_len, u64 flags)",
		"long bpf_sysctl_get_current_value(struct bpf_sysctl *ctx, char *buf, size_t buf_len)",
		"long bpf_sysctl_get_new_value(struct bpf_sysctl *ctx, char *buf, size_t buf_len)",
		"long bpf_sysctl_set_new_value(struct bpf_sysctl *ctx, const char *buf, size_t buf_len)",
		"long bpf_strtol(const char *buf, size_t buf_len, u64 flags, long *res)",
		"long bpf_strtoul(const char *buf, size_t buf_len, u64 flags, unsigned long *res)",
		"void *bpf_sk_storage_get(struct bpf_map *map, void *sk, void *value, u64 flags)",
		"long bpf_sk_storage_delete(struct bpf_map *map, void *sk)",
		"long bpf_send_signal(u32 sig)",
		
		// Helper IDs: 110..119
		"s64 bpf_tcp_gen_syncookie(void *sk, void *iph, u32 iph_len, struct tcphdr *th, u32 th_len)",
		"long bpf_skb_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)",
		"long bpf_probe_read_user(void *dst, u32 size, const void *unsafe_ptr)",
		"long bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)",
		"long bpf_probe_read_user_str(void *dst, u32 size, const void *unsafe_ptr)",
		"long bpf_probe_read_kernel_str(void *dst, u32 size, const void *unsafe_ptr)",
		"long bpf_tcp_send_ack(void *tp, u32 rcv_nxt)",
		"long bpf_send_signal_thread(u32 sig)",
		"u64 bpf_jiffies64(void)",
		"long bpf_read_branch_records(struct bpf_perf_event_data *ctx, void *buf, u32 size, u64 flags)",
		// Helper IDs: 120..129
		"long bpf_get_ns_current_pid_tgid(u64 dev, u64 ino, struct bpf_pidns_info *nsdata, u32 size)",
		"long bpf_xdp_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)",
		"u64 bpf_get_netns_cookie(void *ctx)",
		"u64 bpf_get_current_ancestor_cgroup_id(int ancestor_level)",
		"long bpf_sk_assign(struct bpf_sk_lookup *ctx, struct bpf_sock *sk, u64 flags)",
		"u64 bpf_ktime_get_boot_ns(void)",
		"long bpf_seq_printf(struct seq_file *m, const char *fmt, u32 fmt_size, const void *data, u32 data_len)",
		"long bpf_seq_write(struct seq_file *m, const void *data, u32 len)",
		"u64 bpf_sk_cgroup_id(void *sk)",
		"u64 bpf_sk_ancestor_cgroup_id(void *sk, int ancestor_level)",
		
		// Helper IDs: 130..139
		"long bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags)",
		"void *bpf_ringbuf_reserve(void *ringbuf, u64 size, u64 flags)",
		"void bpf_ringbuf_submit(void *data, u64 flags)",
		"void bpf_ringbuf_discard(void *data, u64 flags)",
		"u64 bpf_ringbuf_query(void *ringbuf, u64 flags)",
		"long bpf_csum_level(struct sk_buff *skb, u64 level)",
		"struct tcp6_sock *bpf_skc_to_tcp6_sock(void *sk)",
		"struct tcp_sock *bpf_skc_to_tcp_sock(void *sk)",
		"struct tcp_timewait_sock *bpf_skc_to_tcp_timewait_sock(void *sk)",
		"struct tcp_request_sock *bpf_skc_to_tcp_request_sock(void *sk)",
		
		// Helper IDs: 140..149
		"struct udp6_sock *bpf_skc_to_udp6_sock(void *sk)",
		"long bpf_get_task_stack(struct task_struct *task, void *buf, u32 size, u64 flags)",
		"long bpf_load_hdr_opt(struct bpf_sock_ops *skops, void *searchby_res, u32 len, u64 flags)",
		"long bpf_store_hdr_opt(struct bpf_sock_ops *skops, const void *from, u32 len, u64 flags)",
		"long bpf_reserve_hdr_opt(struct bpf_sock_ops *skops, u32 len, u64 flags)",
		"void *bpf_inode_storage_get(struct bpf_map *map, void *inode, void *value, u64 flags)",
		"int bpf_inode_storage_delete(struct bpf_map *map, void *inode)",
		"long bpf_d_path(struct path *path, char *buf, u32 sz)",
		"long bpf_copy_from_user(void *dst, u32 size, const void *user_ptr)",
		"long bpf_snprintf_btf(char *str, u32 str_size, struct btf_ptr *ptr, u32 btf_ptr_size, u64 flags)",
		
		// Helper IDs: 150..159
		"long bpf_seq_printf_btf(struct seq_file *m, struct btf_ptr *ptr, u32 ptr_size, u64 flags)",
		"u64 bpf_skb_cgroup_classid(struct sk_buff *skb)",
		"long bpf_redirect_neigh(u32 ifindex, struct bpf_redir_neigh *params, int plen, u64 flags)",
		"void *bpf_per_cpu_ptr(const void *percpu_ptr, u32 cpu)",
		"void *bpf_this_cpu_ptr(const void *percpu_ptr)",
		"long bpf_redirect_peer(u32 ifindex, u64 flags)",
		"void *bpf_task_storage_get(struct bpf_map *map, struct task_struct *task, void *value, u64 flags)",
		"long bpf_task_storage_delete(struct bpf_map *map, struct task_struct *task)",
		"struct task_struct *bpf_get_current_task_btf(void)",
		"long bpf_bprm_opts_set(struct linux_binprm *bprm, u64 flags)",
		
		// Helper IDs: 160..169
		"u64 bpf_ktime_get_coarse_ns(void)",
		"long bpf_ima_inode_hash(struct inode *inode, void *dst, u32 size)",
		"struct socket *bpf_sock_from_file(struct file *file)",
		"long bpf_check_mtu(void *ctx, u32 ifindex, u32 *mtu_len, s32 len_diff, u64 flags)",
		"long bpf_for_each_map_elem(struct bpf_map *map, void *callback_fn, void *callback_ctx, u64 flags)",
		"long bpf_snprintf(char *str, u32 str_size, const char *fmt, u64 *data, u32 data_len)",
		"long bpf_sys_bpf(u32 cmd, void *attr, u32 attr_size)",
		"long bpf_btf_find_by_name_kind(char *name, int name_sz, u32 kind, int flags)",
		"long bpf_sys_close(u32 fd)",
		"long bpf_timer_init(struct bpf_timer *timer, struct bpf_map *map, u64 flags)",
		
		// Helper IDs: 170..179
		"long bpf_timer_set_callback(struct bpf_timer *timer, void *callback_fn)",
		"long bpf_timer_start(struct bpf_timer *timer, u64 nsecs, u64 flags)",
		"long bpf_timer_cancel(struct bpf_timer *timer)",
		"u64 bpf_get_func_ip(void *ctx)",
		"u64 bpf_get_attach_cookie(void *ctx)",
		"long bpf_task_pt_regs(struct task_struct *task)",
		"long bpf_get_branch_snapshot(void *entries, u32 size, u64 flags)",
		"long bpf_trace_vprintk(const char *fmt, u32 fmt_size, const void *data, u32 data_len)",
		"struct unix_sock *bpf_skc_to_unix_sock(void *sk)",
		"long bpf_kallsyms_lookup_name(const char *name, int name_sz, int flags, u64 *res)",
		
		// Helper IDs: 180..189
		"long bpf_find_vma(struct task_struct *task, u64 addr, void *callback_fn, void *callback_ctx, u64 flags)",
		"long bpf_loop(u32 nr_loops, void *callback_fn, void *callback_ctx, u64 flags)",
		"long bpf_strncmp(const char *s1, u32 s1_sz, const char *s2)",
		"long bpf_get_func_arg(void *ctx, u32 n, u64 *value)",
		"long bpf_get_func_ret(void *ctx, u64 *value)",
		"long bpf_get_func_arg_cnt(void *ctx)",
		"int bpf_get_retval(void)",
		"int bpf_set_retval(int retval)",
		"u64 bpf_xdp_get_buff_len(struct xdp_buff *xdp_md)",
		"long bpf_xdp_load_bytes(struct xdp_buff *xdp_md, u32 offset, void *buf, u32 len)",
		
		// Helper IDs: 190..199
		"long bpf_xdp_store_bytes(struct xdp_buff *xdp_md, u32 offset, void *buf, u32 len)",
		"long bpf_copy_from_user_task(void *dst, u32 size, const void *user_ptr, struct task_struct *tsk, u64 flags)",
		"long bpf_skb_set_tstamp(struct sk_buff *skb, u64 tstamp, u32 tstamp_type)",
		"long bpf_ima_file_hash(struct file *file, void *dst, u32 size)",
		"void *bpf_kptr_xchg(void *map_value, void *ptr)",
		"void *bpf_map_lookup_percpu_elem(struct bpf_map *map, const void *key, u32 cpu)",
		"struct mptcp_sock *bpf_skc_to_mptcp_sock(void *sk)",
		"long bpf_dynptr_from_mem(void *data, u32 size, u64 flags, struct bpf_dynptr *ptr)",
		"long bpf_ringbuf_reserve_dynptr(void *ringbuf, u32 size, u64 flags, struct bpf_dynptr *ptr)",
		"void bpf_ringbuf_submit_dynptr(struct bpf_dynptr *ptr, u64 flags)",
		
		// Helper IDs: 200..209
		"void bpf_ringbuf_discard_dynptr(struct bpf_dynptr *ptr, u64 flags)",
		"long bpf_dynptr_read(void *dst, u32 len, const struct bpf_dynptr *src, u32 offset, u64 flags)",
		"long bpf_dynptr_write(const struct bpf_dynptr *dst, u32 offset, void *src, u32 len, u64 flags)",
		"void *bpf_dynptr_data(const struct bpf_dynptr *ptr, u32 offset, u32 len)",
		"s64 bpf_tcp_raw_gen_syncookie_ipv4(struct iphdr *iph, struct tcphdr *th, u32 th_len)",
		"s64 bpf_tcp_raw_gen_syncookie_ipv6(struct ipv6hdr *iph, struct tcphdr *th, u32 th_len)",
		"long bpf_tcp_raw_check_syncookie_ipv4(struct iphdr *iph, struct tcphdr *th)",
		"long bpf_tcp_raw_check_syncookie_ipv6(struct ipv6hdr *iph, struct tcphdr *th)",
		"u64 bpf_ktime_get_tai_ns(void)",
		"long bpf_user_ringbuf_drain(struct bpf_map *map, void *callback_fn, void *ctx, u64 flags)",
		
		// Helper IDs: 210..
		"void *bpf_cgrp_storage_get(struct bpf_map *map, struct cgroup *cgroup, void *value, u64 flags)",
		"long bpf_cgrp_storage_delete(struct bpf_map *map, struct cgroup *cgroup)" 
	};
	//@formatter:on

	private DataTypeManager dtm;
	private FunctionDefinition[] helperFunctionDefs;

	private eBPFHelperDataTypes(DataTypeManager dtm, FunctionDefinition[] helperFunctionDefs) {
		this.dtm = dtm;
		this.helperFunctionDefs = helperFunctionDefs;
	}

	@Override
	public void close() throws IOException {
		helperFunctionDefs = null;
		dtm.close();
	}

	/**
	 * Get eBPF helper function definition for the specified ID.
	 * 
	 * @param id helper function ID
	 * @return eBPF helper function definition or null
	 */
	FunctionDefinition getHelperFunctionDef(int id) {
		if (id >= 0 && id < helperFunctionDefs.length) {
			return helperFunctionDefs[id];
		}
		return null;
	}

	/*******************
	 * Static Methods
	 *******************/

	/**
	 * Get the BPF helper datatypes which has been populated with helper function 
	 * definitions and related dependency datatypes.  All structure dependencies are defined
	 * as empty structures.  In addition, the big-endian typedefs {@code __be16} and 
	 * {@code __be32} will be prepopulated within the program's datatype manager with
	 * big-endian default setting enabled.
	 * 
	 * @param program target program
	 * @param log analysis message log
	 * @return BPF helper datatype or null if failed to initialize.
	 */
	static synchronized eBPFHelperDataTypes get(Program program, MessageLog log) {

		boolean previouslyParsed =
			TransientProgramProperties.hasProperty(program, EBPF_DATATYPE_MGR_PROPERTY_KEY);
		eBPFHelperDataTypes instance = TransientProgramProperties.getProperty(program,
			EBPF_DATATYPE_MGR_PROPERTY_KEY, SCOPE.ANALYSIS_SESSION, eBPFHelperDataTypes.class,
			() -> parseHelpFunctionDefs(program));
		if (instance == null && !previouslyParsed) {
			log.appendMsg("Failed to parse eBPF helper function definitions (see log for details)");
		}
		return instance;
	}

	private static eBPFHelperDataTypes parseHelpFunctionDefs(Program program) {

		FunctionDefinition[] helperFunctionDefs =
			new FunctionDefinition[bpfHelperSignatures.length];

		DataType be16;
		DataType be32;

		boolean success = false;
		DataTypeManager dtm =
			new StandAloneDataTypeManager("BPF", DataOrganizationImpl.getDefaultOrganization());
		int txId = dtm.startTransaction("Parse Types");
		try {

			// Populate typedef dependencies (based upon eBPF.cspec and little-endian)
			dtm.addDataType(new TypedefDataType("u8", UnsignedCharDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("u16", UnsignedShortDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("u32", UnsignedIntegerDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("s32", IntegerDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("u64", UnsignedLongDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("s64", LongDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("__wsum", IntegerDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("__sum16", ShortDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("size_t", UnsignedLongDataType.dataType), null);

			// Define big-endian typedefs - limited support within little-endian program
			be16 = dtm.addDataType(new TypedefDataType("__be16", UnsignedShortDataType.dataType),
				null);
			be32 = dtm.addDataType(new TypedefDataType("__be32", UnsignedIntegerDataType.dataType),
				null);

			CParser parser = new CParser(dtm, true, null);
			try {
				int id = 0;
				for (String def : bpfHelperSignatures) {
					helperFunctionDefs[id++] =
						def != null ? (FunctionDefinition) parser.parse(def + ";") : null;
				}
			}
			catch (ParseException e) {
				Msg.error(eBPFHelperDataTypes.class, "eBPF datatype parse error: " +
					e.getMessage() + "\n\n" + parser.getParseMessages());
				return null;
			}

			success = true;
		}
		finally {
			dtm.endTransaction(txId, true);
			if (!success) {
				dtm.close();
			}
		}

		// Add big-endian datatypes to program and set default setting.
		// This is done since endian settings do not carry through resolve
		program.withTransaction("Add BPF big-endian typedefs", () -> {
			ProgramBasedDataTypeManager programDtm = program.getDataTypeManager();
			setBigEndianFormat(programDtm.addDataType(be16, null));
			setBigEndianFormat(programDtm.addDataType(be32, null));
		});

		return new eBPFHelperDataTypes(dtm, helperFunctionDefs);
	}

	private static void setBigEndianFormat(DataType beDt) {
		Settings defaultSettings = beDt.getDefaultSettings();
		EndianSettingsDefinition.DEF.setBigEndian(defaultSettings, true);
	}

}
