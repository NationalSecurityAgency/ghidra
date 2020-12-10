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
package ghidra.dbg.sctl.protocol.v2012base.x86;

import java.util.List;

import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.common.AbstractByLongFieldsSctlContext;
import ghidra.dbg.sctl.protocol.common.SctlRegisterDefinition;

/**
 * The context packet for SCTL's x86 dialect
 */
public class SctlX86Context extends AbstractByLongFieldsSctlContext {
	@PacketField
	public long r15;
	@PacketField
	public long r14;
	@PacketField
	public long r13;
	@PacketField
	public long r12;
	@PacketField
	public long rbp;
	@PacketField
	public long rbx;
	@PacketField
	public long r11;
	@PacketField
	public long r10;
	@PacketField
	public long r9;
	@PacketField
	public long r8;
	@PacketField
	public long rax;
	@PacketField
	public long rcx;
	@PacketField
	public long rdx;
	@PacketField
	public long rsi;
	@PacketField
	public long rdi;
	@PacketField
	public long orig_rax;
	@PacketField
	public long rip;
	@PacketField
	public long cs;
	@PacketField
	public long eflags;
	@PacketField
	public long rsp;
	@PacketField
	public long ss;
	@PacketField
	public long fs_base;
	@PacketField
	public long gs_base;
	@PacketField
	public long ds;
	@PacketField
	public long es;
	@PacketField
	public long fs;
	@PacketField
	public long gs;

	@Override
	public void setSelectedRegisters(List<SctlRegisterDefinition> regdefs) {
		// Has no effect
	}
}
