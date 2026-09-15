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
package ghidra.app.plugin.core.debug.gui.emulation;

import java.util.Objects;

import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;

abstract class VarRow {
	interface VarRowFactory<T extends VarRow> {
		T create(Language language, String name, VarStorage storage, DataType type);
	}

	static <T extends VarRow> T fromVariable(VarRowFactory<T> cons, Variable v,
			CompilerSpec cSpec) {
		VariableStorage storage = v.getVariableStorage();
		return cons.create(cSpec.getLanguage(), v.getName(),
			VarStorage.fromVariableStorage(storage, cSpec), v.getDataType());
	}

	final Language language;
	final String name;
	final VarStorage storage;
	final int length;
	final Address address;
	final SettingsImpl settings = new SettingsImpl();

	byte[] value;
	String repr;
	DataType type;

	RawStyle style;

	VarRow(Language language, String name, VarStorage storage, DataType type) {
		this.language = language;
		this.name = name;
		this.storage = storage;
		this.length = storage.size();
		this.address = storage.address();

		this.value = new byte[storage.size()];
		this.type = type;
		this.style = RawStyle.defaultForSpace(address.getAddressSpace());

		decodeValue();
	}

	void decodeValue() {
		try {
			if (type == null) {
				repr = null;
				return;
			}
			MemBuffer buf = new ByteMemBufferImpl(address, value, language.isBigEndian()) {
				@Override
				public Language getLanguage() {
					return language;
				}
			};
			repr = type.getRepresentation(buf, settings, length);
		}
		catch (Exception e) {
			Msg.error(this, e.getMessage());
			repr = null;
		}
	}

	String getName() {
		return name;
	}

	VarStorage getStorage() {
		return storage;
	}

	void setType(DataType type) {
		this.type = type;
		decodeValue();
	}

	DataType getType() {
		return type;
	}

	SettingsImpl getSettings() {
		return settings;
	}

	void settingsChanged() {
		decodeValue();
	}

	void setValue(byte[] value) {
		if (value.length != storage.size()) {
			throw new IllegalArgumentException("Length mismatch");
		}
		this.value = value;
		decodeValue();
	}

	byte[] getValue() {
		return value;
	}

	String getValueStr() {
		return style.toString(value, language);
	}

	String getRepr() {
		return Objects.requireNonNullElse(repr, "");
	}
}
