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
package ghidra.app.plugin.core.debug.gui.pcode;

import java.math.BigInteger;
import java.util.stream.Stream;

import ghidra.docking.settings.SettingsImpl;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.NumericUtilities;

public class UniqueRow {
	public enum RefType {
		NONE, READ, WRITE, READ_WRITE;

		static RefType fromRW(boolean isRead, boolean isWrite) {
			if (isRead) {
				if (isWrite) {
					return READ_WRITE;
				}
				else {
					return READ;
				}
			}
			else {
				if (isWrite) {
					return WRITE;
				}
				else {
					return NONE;
				}
			}
		}
	}

	protected final DebuggerPcodeStepperProvider provider;
	protected final Language language;
	protected final PcodeExecutorState<byte[]> state;
	protected final Varnode vn;

	protected DataType dataType;

	public UniqueRow(DebuggerPcodeStepperProvider provider, Language language,
			PcodeExecutorState<byte[]> state, Varnode vn) {
		if (!vn.isUnique()) {
			throw new AssertionError("Only uniques allowed in unique table");
		}
		this.provider = provider;
		this.language = language;
		this.state = state;
		this.vn = vn;
	}

	protected static AddressRange rangeOf(Varnode vn) {
		try {
			return new AddressRangeImpl(vn.getAddress(), vn.getSize());
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	protected static boolean overlap(Varnode vn1, Varnode vn2) {
		return rangeOf(vn1).intersects(rangeOf(vn2));
	}

	public RefType getRefType() {
		int index = provider.pcodeTable.getSelectedRow();
		if (index == -1) {
			return RefType.NONE;
		}
		PcodeRow row = provider.pcodeTableModel.getRowObject(index);
		PcodeOp op = row.getOp();
		if (op == null) {
			return RefType.NONE;
		}
		boolean isRead = Stream.of(op.getInputs()).anyMatch(in -> overlap(in, vn));
		Varnode out = op.getOutput();
		boolean isWrite = out != null && overlap(out, vn);
		return RefType.fromRW(isRead, isWrite);
	}

	public String getName() {
		return PcodeProgram.uniqueToString(vn, false);
	}

	public String getBytes() {
		// TODO: Could keep value cached?
		byte[] bytes = state.getVar(vn);
		if (bytes == null) {
			return "??";
		}
		if (bytes.length > 20) {
			return NumericUtilities.convertBytesToString(bytes, 0, 20, " ") + " ...";
		}
		return NumericUtilities.convertBytesToString(bytes, " ");
	}

	public BigInteger getValue() {
		byte[] bytes = state.getVar(vn);
		return Utils.bytesToBigInteger(bytes, bytes.length, language.isBigEndian(), false);
	}

	public DataType getDataType() {
		return dataType;
	}

	public void setDataType(DataType dataType) {
		this.dataType = dataType;
	}

	public String getValueRepresentation() {
		// TODO: Could compute this upon setting data type?
		if (dataType == null) {
			return "";
		}
		byte[] bytes = state.getVar(vn);
		if (bytes == null) {
			return "??";
		}
		MemBuffer buffer = new ByteMemBufferImpl(vn.getAddress(), bytes, language.isBigEndian());
		return dataType.getRepresentation(buffer, SettingsImpl.NO_SETTINGS, bytes.length);
	}
}
