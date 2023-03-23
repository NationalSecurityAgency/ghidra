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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractProcedureMsType;

/**
 * Procedure Flags for certain PDB symbols.
 * <P>
 * Class describes the function return method.
 */
public class ProcedureFlags extends AbstractParsableItem {

	private int flagByte;

	/**
	 * Constructor for this symbol component.
	 * @param reader {@link PdbByteReader} from which this data is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public ProcedureFlags(PdbByteReader reader) throws PdbException {
		flagByte = reader.parseUnsignedByteVal();
	}

	@Override
	public void emit(StringBuilder builder) {
		DelimiterState ds = new DelimiterState("", ", ");
		builder.append("Flags: ");
		builder.append(ds.out(hasFramePointerPresent(), "Frame Ptr Present"));
		builder.append(ds.out(hasInterruptReturn(), "Interrupt"));
		builder.append(ds.out(hasFarReturn(), "FAR"));
		builder.append(ds.out(doesNotReturn(), "Never Return"));
		builder.append(ds.out(labelNotReached(), "Not Reached"));
		builder.append(ds.out(hasCustomCallingConvention(), "Custom Calling Convention"));
		builder.append(ds.out(markedAsNoInline(), "Do Not Inline"));
		builder.append(ds.out(hasDebugInformationForOptimizedCode(), "Optimized Debug Info"));
	}

	/**
	 * Indicates if has frame pointer present
	 * @return true if frame pointer is present
	 */
	public boolean hasFramePointerPresent() {
		return (flagByte & 0x0001) == 0x0001;
	}

	/**
	 * Indicates if has a an interrupt return
	 * @return true if has an interrupt return
	 */
	public boolean hasInterruptReturn() {
		return (flagByte & 0x0002) == 0x0002;
	}

	/**
	 * Indicates if has a far return
	 * @return true if has a far return
	 */
	public boolean hasFarReturn() {
		return (flagByte & 0x0004) == 0x0004;
	}

	/**
	 * Indicates if does not return
	 * @return true if does not return
	 */
	public boolean doesNotReturn() {
		return (flagByte & 0x0008) == 0x0008;
	}

	/**
	 * Indicates if label is not reached
	 * @return true if label is not reached
	 */
	public boolean labelNotReached() {
		return (flagByte & 0x0010) == 0x0010;
	}

	/**
	 * Indicates if has custom calling convention.
	 * <p>
	 * Not sure how this is weighed against a function spec that has a valid calling convention,
	 * when a function symbol will have both this {@link ProcedureFlags} and a
	 * {@link AbstractProcedureMsType} function spec with the calling convention.
	 * @return true if has custom calling convention
	 */
	public boolean hasCustomCallingConvention() {
		return (flagByte & 0x0020) == 0x0020;
	}

	/**
	 * Indicates if marked as {@code noinline}
	 * @return true if marked as {@code noinline}
	 */
	public boolean markedAsNoInline() {
		return (flagByte & 0x0040) == 0x0040;
	}

	/**
	 * Indicates if has debug information for optimized code
	 * @return true if has debug information for optimized code
	 */
	public boolean hasDebugInformationForOptimizedCode() {
		return (flagByte & 0x0080) == 0x0080;
	}

}
