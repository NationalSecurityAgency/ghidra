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
package ghidra.dbg.sctl.protocol.v2018base.any;

import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.common.AbstractSctlObjectEntry;
import ghidra.dbg.sctl.protocol.common.SctlString;

/**
 * The format for each process of {@code bytes[]} of SCTL's {@code Rps} reply for Linux dialects
 */
public class Sctl2018ObjectEntry extends AbstractSctlObjectEntry {
	@PacketField
	public SctlString path;

	@PacketField
	public SctlString key;

	@PacketField
	public SctlString kind;

	@PacketField
	public SctlString value;

	@PacketField
	public SctlString type;

	@Override
	public SctlString getPath() {
		return path;
	}

	@Override
	public void setPath(SctlString path) {
		this.path = path;
	}

	@Override
	public SctlString getKey() {
		return key;
	}

	@Override
	public void setKey(SctlString key) {
		this.key = key;
	}

	@Override
	public SctlString getKind() {
		return kind;
	}

	@Override
	public void setKind(SctlString kind) {
		this.kind = kind;
	}

	@Override
	public SctlString getValue() {
		return value;
	}

	@Override
	public void setValue(SctlString value) {
		this.value = value;
	}

	@Override
	public SctlString getType() {
		return type;
	}

	@Override
	public void setType(SctlString type) {
		this.type = type;
	}

}
