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

import java.util.ArrayList;
import java.util.List;

import ghidra.comm.packet.annot.CountedByField;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.AbstractSctlRequest;
import ghidra.dbg.sctl.protocol.common.SctlString;

/**
 * Format for the {@code Tlaunch} SCTL message
 * 
 * Technically, this should be dialect dependent, but it appears both dialects in the reference
 * implementations use this same format.
 */
// TODO: Use an abstract placeholder if this turns out to be a dialect-dependent extension point
public class SctlLaunchRequest extends AbstractSctlRequest {
	public SctlLaunchRequest() {
	}

	public SctlLaunchRequest(List<String> args) {
		this.args = new ArrayList<>();
		for (String arg : args) {
			this.args.add(new SctlString(arg));
		}
	}

	@PacketField
	public long flags;

	@PacketField
	public long narg;

	@PacketField
	@RepeatedField
	@CountedByField("narg")
	public List<SctlString> args;
}
