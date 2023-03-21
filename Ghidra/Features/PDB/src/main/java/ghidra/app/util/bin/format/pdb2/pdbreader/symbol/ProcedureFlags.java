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

	private static final int HAS_FRAME_POINTER_PRESENT = 0x0001;
	private static final int HAS_INTERRUPT_RETURN = 0x0002;
	private static final int HAS_FAR_RETURN = 0x0004;
	private static final int DOES_NOT_RETURN = 0x0008;
	private static final int LABEL_NOT_REACHED = 0x0010;
	private static final int HAS_CUSTOM_CALLING_CONVENTION = 0x0020;
	private static final int MARKED_AS_NO_INLINE = 0x0040;
	private static final int HAS_DEBUG_INFORMATION_FOR_OPTIMIZED_CODE = 0x0080;

	private static final int FUNCTION_INDICATION =
		HAS_FRAME_POINTER_PRESENT | HAS_INTERRUPT_RETURN | HAS_FAR_RETURN | DOES_NOT_RETURN |
			LABEL_NOT_REACHED | HAS_CUSTOM_CALLING_CONVENTION | MARKED_AS_NO_INLINE |
			HAS_DEBUG_INFORMATION_FOR_OPTIMIZED_CODE;

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
		return (flagByte & HAS_FRAME_POINTER_PRESENT) != 0;
	}

	/**
	 * Indicates if has a an interrupt return
	 * @return true if has an interrupt return
	 */
	public boolean hasInterruptReturn() {
		return (flagByte & HAS_INTERRUPT_RETURN) != 0;
	}

	/**
	 * Indicates if has a far return
	 * @return true if has a far return
	 */
	public boolean hasFarReturn() {
		return (flagByte & HAS_FAR_RETURN) != 0;
	}

	/**
	 * Indicates if does not return
	 * @return true if does not return
	 */
	public boolean doesNotReturn() {
		return (flagByte & DOES_NOT_RETURN) != 0;
	}

	/**
	 * Indicates if label is not reached
	 * @return true if label is not reached
	 */
	public boolean labelNotReached() {
		return (flagByte & LABEL_NOT_REACHED) != 0;
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
		return (flagByte & HAS_CUSTOM_CALLING_CONVENTION) != 0;
	}

	/**
	 * Indicates if marked as {@code noinline}
	 * @return true if marked as {@code noinline}
	 */
	public boolean markedAsNoInline() {
		return (flagByte & MARKED_AS_NO_INLINE) != 0;
	}

	/**
	 * Indicates if has debug information for optimized code
	 * @return true if has debug information for optimized code
	 */
	public boolean hasDebugInformationForOptimizedCode() {
		return (flagByte & HAS_DEBUG_INFORMATION_FOR_OPTIMIZED_CODE) != 0;
	}

	/**
	 * Returns true if seems like a function.  Not necessary, but (seems) sufficient, to indicate a
	 *  function (this is Ghidra functionality not specified in PDB API)
	 * @return true if function indicated
	 */
	public boolean hasFunctionIndication() {
		return (flagByte & FUNCTION_INDICATION) != 0x0000;
	}
}
