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
package ghidra.dbg.sctl.protocol.common.request;

import ghidra.comm.packet.annot.BitmaskEncoded;
import ghidra.comm.packet.fields.PacketField;
import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.sctl.protocol.AbstractSctlRequest;
import ghidra.dbg.sctl.protocol.consts.Evkind;

/**
 * Format for the {@code Ttrace} SCTL message
 */
public class SctlTraceRequest extends AbstractSctlRequest {
	public SctlTraceRequest() {
	}

	public SctlTraceRequest(long ctlid, BitmaskSet<Evkind> flags) {
		this.ctlid = ctlid;
		this.flags = flags;
	}

	@PacketField
	public long ctlid;

	@PacketField
	@BitmaskEncoded(universe = Evkind.class)
	public BitmaskSet<Evkind> flags;
}
