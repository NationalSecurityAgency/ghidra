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

import java.util.Arrays;
import java.util.Set;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeEncodeException;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

class InputRow extends VarRow {
	static InputRow fromVariable(Variable v, CompilerSpec cSpec) {
		return VarRow.fromVariable(InputRow::new, v, cSpec);
	}

	final Set<String> depsByName; // Use names since the actual row can be replaced by refresh

	InputRow(Language language, String name, VarStorage storage, DataType type,
			Set<String> depsByName) {
		super(language, name, storage, type);
		this.depsByName = depsByName;
	}

	InputRow(Language language, String name, VarStorage storage, DataType type) {
		this(language, name, storage, type, Set.of());
	}

	private void encodeRepr() throws DataTypeEncodeException {
		MemBuffer buf = new ByteMemBufferImpl(address, value, language.isBigEndian());
		byte[] data = type.encodeRepresentation(repr, buf, settings, length);
		if (data.length == length) {
			value = data;
		}
		else {
			value = Arrays.copyOf(data, length);
		}
	}

	void setValueStr(String string) {
		RawStyle style = RawStyle.fromString(string);
		byte[] value = style.fromString(string, length, language);
		this.style = style;
		this.value = value;
		decodeValue();
	}

	void setRepr(String repr) {
		String oldRepr = this.repr;
		this.repr = repr;
		try {
			encodeRepr();
			decodeValue();
		}
		catch (DataTypeEncodeException e) {
			this.repr = oldRepr;
			throw new IllegalArgumentException(e.getMessage(), e);
		}
	}

	boolean isReprEditable() {
		return repr != null && type.isEncodable();
	}
}
