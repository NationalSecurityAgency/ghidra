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

import java.util.*;

import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.common.AbstractSctlContext;
import ghidra.dbg.sctl.protocol.common.SctlRegisterDefinition;

public class Sctl2018Context extends AbstractSctlContext {
	protected class RegisterCodec {
		final int start;
		final int byteLen;

		public RegisterCodec(int start, int byteLen) {
			this.start = start;
			this.byteLen = byteLen;
		}

		public void encode(byte[] val) {
			System.arraycopy(val, 0, data, start, byteLen);
		}

		public void decode(byte[] val) {
			System.arraycopy(data, start, val, 0, byteLen);
		}

		public byte[] decode() {
			byte[] val = new byte[byteLen];
			decode(val);
			return val;
		}
	}

	//private final List<SctlRegisterDefinition> regdefs;
	private final Map<String, RegisterCodec> codecsByName = new LinkedHashMap<>();
	private final Set<String> names = new LinkedHashSet<>();
	private final Set<String> namesView =
		Collections.unmodifiableSet(names);
	private final Map<String, byte[]> valuesByName = new LinkedHashMap<>();
	private final Map<String, byte[]> valuesView = Collections.unmodifiableMap(valuesByName);

	private int totalLen;

	public Sctl2018Context() {
	}

	@Override
	public void setSelectedRegisters(List<SctlRegisterDefinition> regdefs) {
		int byteLoc = 0;
		codecsByName.clear();
		for (SctlRegisterDefinition def : regdefs) {
			int byteLen = (int) ((def.nbits + 7) / 8);
			codecsByName.put(def.name.str, new RegisterCodec(byteLoc, byteLen));
			names.add(def.name.str);
			byteLoc += byteLen;
		}
		totalLen = byteLoc;
		checkData();
		parseData();
	}

	public void setData(byte[] data) {
		if (totalLen != data.length) {
			throw new IllegalArgumentException(
				"data length must match total from selected registers");
		}
		System.arraycopy(data, 0, this.data, 0, totalLen);
		parseData();
	}

	protected void parseData() {
		valuesByName.clear();
		if (data == null) {
			return;
		}
		for (Map.Entry<String, RegisterCodec> ent : codecsByName.entrySet()) {
			valuesByName.put(ent.getKey(), ent.getValue().decode());
		}
	}

	@Override
	public Map<String, byte[]> toMap() {
		return valuesView;
	}

	@Override
	public Set<String> getRegisterNames() {
		return namesView;
	}

	protected void checkData() {
		if (data == null) {
			data = new byte[totalLen];
		}
	}

	@Override
	public void updateFromMap(Map<String, byte[]> values) {
		for (Map.Entry<String, byte[]> ent : values.entrySet()) {
			String name = ent.getKey();
			byte[] value = ent.getValue();
			doUpdate(name, value);
		}
	}

	protected void doUpdate(String name, byte[] value) {
		RegisterCodec codec = codecsByName.get(name);
		if (codec == null) {
			throw new IllegalArgumentException("Register invalid or not selected: " + name);
		}
		if (value.length != codec.byteLen) {
			throw new IllegalArgumentException("Register value for " + name +
				" has incorrect length: " + value.length + ". Expected " + codec.byteLen);
		}
		codec.encode(value);
		valuesByName.put(name, value);
	}

	@Override
	public void update(String name, byte[] value) {
		doUpdate(name, value);
	}

	@PacketField
	public byte[] data;
}
