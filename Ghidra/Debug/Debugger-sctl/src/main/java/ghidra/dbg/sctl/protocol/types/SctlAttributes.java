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
package ghidra.dbg.sctl.protocol.types;

import java.util.ArrayList;
import java.util.List;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.CountedByField;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.fields.PacketField;

/**
 * The format for {@code attrs} in SCTL
 */
public class SctlAttributes extends Packet {
	public static SctlAttributes empty() {
		SctlAttributes attrs = new SctlAttributes();
		attrs.pairs = new ArrayList<>();
		return attrs;
	}

	@PacketField
	public long na;

	@PacketField
	@RepeatedField
	@CountedByField("na")
	public List<SctlAttributeKeyVal> pairs;
}
