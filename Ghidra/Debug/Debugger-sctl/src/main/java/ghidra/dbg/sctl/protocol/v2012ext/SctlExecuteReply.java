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
package ghidra.dbg.sctl.protocol.v2012ext;

import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.client.SctlExtension;
import ghidra.dbg.sctl.protocol.AbstractSctlReply;
import ghidra.dbg.sctl.protocol.common.SctlString;

/**
 * Format for the "{@code Rexec}" SCTL message
 * 
 * There is no {@code Texec} or {@code Rexec} in the official SCTL protocol. It is an extension for
 * Ghidra to issue CLI commands to a connected interactive debugger.
 */
@SctlExtension("Response to CLI command in remote debugger")
public class SctlExecuteReply extends AbstractSctlReply {
	public SctlExecuteReply() {
	}

	public SctlExecuteReply(String out) {
		this.out = new SctlString(out);
	}

	@PacketField
	public SctlString out;
}
