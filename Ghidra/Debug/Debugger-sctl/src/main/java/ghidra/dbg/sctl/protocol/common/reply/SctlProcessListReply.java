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
package ghidra.dbg.sctl.protocol.common.reply;

import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.AbstractSctlReply;
import ghidra.dbg.sctl.protocol.common.AbstractSctlProcessList;

/**
 * Format for the {@code Rps} SCTL message
 */
public class SctlProcessListReply extends AbstractSctlReply {
	public SctlProcessListReply() {
	}

	public SctlProcessListReply(AbstractSctlProcessList pslist) {
		this.pslist = pslist;
	}

	// TODO: If a dialect arises where this format differs, I will need to re-factor.
	@PacketField
	public AbstractSctlProcessList pslist;
}
