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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

/**
 * Frame Pointer Omission Data, according to API, represents stack frame layout on x86 when
 *  frame pointer omission optimization is used.  This structure is used to locate the call frame.
 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_fpo_data">
 * MSFT Documentation</a>, which specifies:
 * <PRE>
 *   typedef struct _FPO_DATA {
 *     DWORD ulOffStart;
 *     DWORD cbProcSize;
 *     DWORD cdwLocals;
 *     WORD  cdwParams;
 *     WORD  cbProlog : 8;
 *     WORD  cbRegs : 3;
 *     WORD  fHasSEH : 1;
 *     WORD  fUseBP : 1;
 *     WORD  reserved : 1;
 *     WORD  cbFrame : 2;
 *   } FPO_DATA, *PFPO_DATA;
 *   
 *   where...
 *   ulOffStart = The offset of the first byte of the function code.
 *   cbProcSize = The number of bytes in the function.
 *   cdwLocals = the number of local variables.
 *   cdwParams = The size of the parameters, in DWORDs.
 *   cbProlog = The number of bytes in the function prolog code.
 *   cbRegs = The number of registers saved.
 *   fHasSEH = A variable that indicates whether the function used structured exeception handling.
 *   fUseBP = A variable that indicates whether the EBP register has been allocated.
 *   reserved = Reserved for future use.
 *   cbFrame = A variable that indicates the frame type, where...
 *     FRAME_FPO (0) = FPO frame
 *     FRAME_TRAP (1) = Trap frame
 *     FRAME_TSS (2) = TSS frame 
 *     FRAME_NONFPO (3) = non-FPO frame
 * </PRE>
 */
public class FramePointerOmissionRecord {

	public enum FrameType {
		FPO("fpo", 0), TRAP("trap", 1), TSS("tss", 2), NON_FPO("std", 3);

		private static final Map<Integer, FrameType> BY_VALUE = new HashMap<>();
		static {
			for (FrameType val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		private final int value;

		@Override
		public String toString() {
			return label;
		}

		public static FrameType fromValue(int val) {
			return BY_VALUE.getOrDefault(val, FPO);
		}

		private FrameType(String label, int value) {
			this.label = label;
			this.value = value;
		}

	}

	private long firstFunctionByteOffset;
	private long numFunctionBytes;
	private long numLocalVariables;
	private int sizeOfParametersInDwords;
	private int numFunctionPrologBytes;
	private boolean hasStructuredExceptionHandling;
	private boolean ebpAllocatedAndUsed;
	private int reserved;
	private FrameType frameType;

	/**
	 * Returns the offset of the first byte of the function.
	 * @return the offset.
	 */
	public long getFirstFunctionByteOffset() {
		return firstFunctionByteOffset;
	}

	/**
	 * Returns the number of bytes in the function.
	 * @return the number of bytes in the function.
	 */
	public long getNumberOfFunctionBytes() {
		return numFunctionBytes;
	}

	/**
	 * Returns the number of local variables.
	 * @return the number of local variables.
	 */
	public long getNumberLocalVariables() {
		return numLocalVariables;
	}

	/**
	 * Returns the size of the parameter as the number of DWORDs.
	 * @return the size of the parameters in DWORDs.
	 */
	public int getSizeOfParametersInDwords() {
		return sizeOfParametersInDwords;
	}

	/**
	 * Returns the number of bytes in the function prolog.
	 * @return the number of bytes in the prolog.
	 */
	public int getNumberFunctionPrologBytes() {
		return numFunctionPrologBytes;
	}

	/**
	 * Returns whether there the function has structured exception handling.
	 * @return whether structure handling is used.
	 */
	public boolean hasStructuredExceptionHandling() {
		return hasStructuredExceptionHandling;
	}

	/**
	 * Returns whether the EBP is allocated/used.
	 * @return whether EBP is allocated/used.
	 */
	public boolean EBPAllocatedAndUsed() {
		return ebpAllocatedAndUsed;
	}

	/**
	 * Returns the value of the reserved 1-bit field..
	 * @return the value of the reserved field.
	 */
	public int reserved() {
		return reserved;
	}

	/**
	 * Returns the {@link FrameType} being specified.
	 * @return the {@link FrameType} being specified.
	 */
	public FrameType getFrameType() {
		return frameType;
	}

	public void parse(PdbByteReader reader) throws PdbException {
		if (reader.numRemaining() < 16) {
			throw new PdbException("Not enough data for FramePointerOmissionRecord");
		}
		firstFunctionByteOffset = reader.parseUnsignedIntVal();
		numFunctionBytes = reader.parseUnsignedIntVal();
		numLocalVariables = reader.parseUnsignedIntVal();
		sizeOfParametersInDwords = reader.parseUnsignedShortVal();
		int data = reader.parseUnsignedShortVal();
		numFunctionPrologBytes = (data & 0xff);
		data >>= 8;
		hasStructuredExceptionHandling = (data & 0x01) == 0x01;
		data >>= 1;
		ebpAllocatedAndUsed = (data & 0x01) == 0x01;
		data >>= 1;
		reserved = data & 0x01;
		data >>= 1;
		frameType = FrameType.fromValue(data & 0x03);
	}

	/**
	 * Dumps the {@link FramePointerOmissionRecord}.  This package-protected method is for
	 *  debugging only.
	 * @param writer {@link Writer} to which to write the debug dump.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	void dump(Writer writer) throws IOException {
		writer.write("FramePointerOmissionRecord----------------------------------\n");
		writer.write(String.format("firstFunctionByteOffset: 0X%08X\n", firstFunctionByteOffset));
		writer.write(String.format("firstFunctionByteOffset: 0X%08X\n", firstFunctionByteOffset));
		writer.write(String.format("numFunctionBytes: 0X%08XX\n", numFunctionBytes));
		writer.write(String.format("numLocalVariables: 0X%08X\n", numLocalVariables));
		writer.write(String.format("sizeOfParametersInDwords: 0X%08X\n", sizeOfParametersInDwords));
		writer.write(String.format("numFunctionPrologBytes: 0X%04X\n", numFunctionPrologBytes));
		writer.write(String.format("hasStructuredExceptionHandling: %s\n",
			Boolean.toString(hasStructuredExceptionHandling)));
		writer.write(
			String.format("EBPAllocatedAndUsed: %s\n", Boolean.toString(ebpAllocatedAndUsed)));
		writer.write(String.format("reserved: 0X%01X\n", reserved));
		writer.write(String.format("frameType: %s\n", frameType.toString()));
		writer.write("End FramePointerOmissionRecord------------------------------\n");
	}
}
