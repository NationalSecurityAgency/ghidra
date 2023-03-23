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
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeExecutorState;
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
				return READ;
			}
			if (isWrite) {
				return WRITE;
			}
			return NONE;
		}
	}

	/**
	 * Putting these related methods, all using a common type, into a nested class allows us to
	 * introduce {@code <T>}, essentially a "universal type."
	 * 
	 * @param <T> the type of state from which concrete parts are extracted.
	 */
	public static class ConcretizedState<T> {
		private final PcodeExecutorState<T> state;
		private final PcodeArithmetic<T> arithmetic;

		public ConcretizedState(PcodeExecutorState<T> state, PcodeArithmetic<T> arithmetic) {
			this.state = state;
			this.arithmetic = arithmetic;
		}

		public byte[] getBytes(Varnode vn) {
			return arithmetic.toConcrete(state.getVar(vn, Reason.INSPECT), Purpose.INSPECT);
		}

		public BigInteger getValue(Varnode vn) {
			return arithmetic.toBigInteger(state.getVar(vn, Reason.INSPECT), Purpose.INSPECT);
		}
	}

	protected final DebuggerPcodeStepperProvider provider;
	protected final Language language;
	protected final ConcretizedState<?> state;
	protected final Varnode vn;

	protected DataType dataType;

	public <T> UniqueRow(DebuggerPcodeStepperProvider provider, Language language,
			PcodeExecutorState<T> state, PcodeArithmetic<T> arithmetic, Varnode vn) {
		if (!vn.isUnique()) {
			throw new AssertionError("Only uniques allowed in unique table");
		}
		this.provider = provider;
		this.language = language;
		this.state = new ConcretizedState<>(state, arithmetic);
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
		return String.format("$U%x:%d", vn.getOffset(), vn.getSize());
	}

	// TODO: Pluggable columns to display abstract pieces

	/**
	 * Renders the raw bytes as space-separated hexadecimal-digit pairs, if concrete
	 * 
	 * <p>
	 * If the state's concrete piece cannot be extracted by the machine's arithmetic, this simply
	 * returns {@code "(not concrete)"}.
	 * 
	 * @return the byte string
	 */
	public String getBytes() {
		// TODO: Could keep value cached?
		byte[] bytes;
		try {
			bytes = state.getBytes(vn);
		}
		catch (UnsupportedOperationException e) {
			return "(not concrete)";
		}
		if (bytes == null) {
			return "??";
		}
		if (bytes.length > 20) {
			return NumericUtilities.convertBytesToString(bytes, 0, 20, " ") + " ...";
		}
		return NumericUtilities.convertBytesToString(bytes, " ");
	}

	/**
	 * Extract the concrete part of the variable as an unsigned big integer
	 * 
	 * @return the value, or null if the value cannot be made concrete
	 */
	public BigInteger getValue() {
		try {
			return state.getValue(vn);
		}
		catch (UnsupportedOperationException e) {
			return null;
		}
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
		byte[] bytes = state.getBytes(vn);
		if (bytes == null) {
			return "??";
		}
		MemBuffer buffer = new ByteMemBufferImpl(vn.getAddress(), bytes, language.isBigEndian());
		return dataType.getRepresentation(buffer, SettingsImpl.NO_SETTINGS, bytes.length);
	}
}
