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
package ghidra.app.plugin.core.debug.gui.variable;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

import ghidra.app.services.DebuggerControlService;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeEncodeException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

import static ghidra.docking.settings.SettingsImpl.NO_SETTINGS;

public abstract class AbstractDebuggerVariableViewerVarValue {
	byte[] oldValue;
	TraceMemoryState state;
	String repr;
	Language language;
	byte[] value;
	Address address;
	DebuggerVariableViewerProvider provider;
	String error;

	AbstractDebuggerVariableViewerVarValue(byte[] value, Address address, String repr,
			DebuggerVariableViewerProvider provider, String error, TraceMemoryState state) {
		this.value = value;
		this.oldValue = value;
		this.address = Objects.requireNonNull(address);
		this.provider = Objects.requireNonNull(provider);
		this.repr = Objects.requireNonNullElse(repr, "");
		this.error = error;
		language = provider.currentCoordinates.getLanguage();
		this.state = state;
	}

	public void setOldValue(byte[] oldValue) {
		this.oldValue = oldValue;
	}

	public boolean isKnown() {
		return state == TraceMemoryState.KNOWN;
	}

	public boolean canEdit() {
		if (this.language == null) {
			return false;
		}
		if (this.value == null) {
			return false;
		}
		if (this.error != null) {
			return false;
		}
		if (address == Address.NO_ADDRESS) {
			return false;
		}

		DebuggerControlService controlService = provider.controlService;
		if (controlService == null) {
			return false;
		}
		DebuggerControlService.StateEditor editor =
				controlService.createStateEditor(provider.currentCoordinates);
		return editor.isVariableEditable(address, value.length);
	}

	public Address getAddress() {
		return address;
	}

	public String getRepr() {
		return repr;
	}

	public void setRepr(String reprValue) {
		if ((getDataType() == null) || (value == null)) {
			Msg.error(this, "No value or no data type");
			return;
		}
		try {
			final byte[] encoded = getDataType().encodeRepresentation(reprValue,
					new ByteMemBufferImpl(address, value, language.isBigEndian()), NO_SETTINGS,
					value.length);
			setRawValueBytes(encoded);
		}
		catch (final DataTypeEncodeException e) {
			Msg.error(this, e.getMessage());
		}
	}

	abstract DataType getDataType();

	abstract void setDataType(DataType dataType);

	private void setRawValueBytes(byte[] bytes) {
		if (address == null) {
			throw new IllegalStateException("Cannot write to variable without an address");
		}
		if (bytes.length > value.length) {
			throw new IllegalArgumentException("Byte arrays cannot exceed length of variable");
		}
		if (bytes.length < value.length) {
			final byte[] fillOld = Arrays.copyOf(value, value.length);
			System.arraycopy(bytes, 0, fillOld, 0, bytes.length);
			bytes = fillOld;
		}
		final DebuggerControlService controlService = provider.controlService;
		if (controlService == null) {
			throw new AssertionError("No control service");
		}
		final DebuggerControlService.StateEditor editor =
				controlService.createStateEditor(provider.currentCoordinates);
		editor.setVariable(address, bytes).exceptionally(ex -> {
			Msg.showError(this, null, "Write Failed", "Could not modify value (on target)", ex);
			return null;
		});

	}

	abstract String getSource();

	abstract String getSymbol();

	abstract void setSymbol(String symbol);

	public String getValue() {
		if ((value == null) || (language == null)) {
			return "??";
		}
		if (value.length <= address.getPointerSize() || !address.isMemoryAddress()) {
			final BigInteger asBigInt =
					Utils.bytesToBigInteger(value, value.length, language.isBigEndian(), false);
			return "0x" + asBigInt.toString(16);
		}
		else if (value.length > 64) {
			// TODO: I'd like this not to affect the actual value, just the display esp., since
			//  this will be the "value" when starting to edit.
			return "{ " + NumericUtilities.convertBytesToString(value, 0, 64, " ") + " ... }";
		}
		return "{ " + NumericUtilities.convertBytesToString(value, " ") + " }";
	}

	public void setValue(String valueString) {
		if ((value == null) || (language == null)) {
			throw new AssertionError("Value and language cannot be null");
		}
		if ((getDataType() == null) || (value == null)) {
			// isValueEditable should have been false
			Msg.error(this, "No value or no data type");
			return;
		}

		valueString = valueString.trim();
		if (valueString.startsWith("{")) {
			if (!valueString.endsWith("}")) {
				throw new NumberFormatException("Byte array values must be hex enclosed in {}");
			}

			setRawValueBytesString(valueString.substring(1, valueString.length() - 1));
			return;
		}

		setRawValueIntString(valueString);
	}

	private void setRawValueBytesString(String bytesString) {
		setRawValueBytes(NumericUtilities.convertStringToBytes(bytesString));
	}

	private void setRawValueIntString(String intString) {
		intString = intString.trim();
		final BigInteger val;
		if (intString.startsWith("0x")) {
			val = new BigInteger(intString.substring(2), 16);
		}
		else {
			val = new BigInteger(intString, 10);
		}
		setRawValueBytes(Utils.bigIntegerToBytes(val, value.length, language.isBigEndian()));
	}

	public String getError() {
		return error;
	}

	public boolean isChanged() {
		return !Arrays.equals(value, oldValue);
	}

	public Language getLanguage() {
		return this.language;
	}
}
