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

/**
 * Procedure Flags for certain PDB symbols.
 * <P>
 * Class describes the function return method.
 */
public class ProcedureFlags extends AbstractParsableItem {

	private int flagByte;

	private boolean framePointerPresent;
	private boolean interruptReturn;
	private boolean farReturn;
	private boolean doesNotReturn;
	private boolean labelNotReached;
	private boolean customCallingConvention;
	private boolean markedAsNoInline;
	private boolean hasDebugInformationForOptimizedCode;

	/**
	 * Constructor for this symbol component.
	 * @param reader {@link PdbByteReader} from which this data is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public ProcedureFlags(PdbByteReader reader) throws PdbException {
		flagByte = reader.parseUnsignedByteVal();
		processFlags(flagByte);
	}

	@Override
	public void emit(StringBuilder builder) {
		DelimiterState ds = new DelimiterState("", ", ");
		builder.append("Flags: ");
		builder.append(ds.out(framePointerPresent, "Frame Ptr Present"));
		builder.append(ds.out(interruptReturn, "Interrupt"));
		builder.append(ds.out(farReturn, "FAR"));
		builder.append(ds.out(doesNotReturn, "Never Return"));
		builder.append(ds.out(labelNotReached, "Not Reached"));
		builder.append(ds.out(customCallingConvention, "Custom Calling Convention"));
		builder.append(ds.out(markedAsNoInline, "Do Not Inline"));
		builder.append(ds.out(hasDebugInformationForOptimizedCode, "Optimized Debug Info"));
	}

	private void processFlags(int val) {
		framePointerPresent = ((val & 0x0001) == 0x0001);
		val >>= 1;
		interruptReturn = ((val & 0x0001) == 0x0001);
		val >>= 1;
		farReturn = ((val & 0x0001) == 0x0001);
		val >>= 1;
		doesNotReturn = ((val & 0x0001) == 0x0001);
		val >>= 1;
		labelNotReached = ((val & 0x0001) == 0x0001);
		val >>= 1;
		customCallingConvention = ((val & 0x0001) == 0x0001);
		val >>= 1;
		markedAsNoInline = ((val & 0x0001) == 0x0001);
		val >>= 1;
		hasDebugInformationForOptimizedCode = ((val & 0x0001) == 0x0001);
	}

}
