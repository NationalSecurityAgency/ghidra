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

/**
 * FRAMEDATA from cvinfo.h
 *   Most members are coded as unsigned long or unsigned long bit-fields; two are coded as
 *   unsigned short: prolog and saved regs.
 */
public class FrameDataRecord {

	private long rvaStart; // unsigned long
	private long numBlockBytes; // unsigned long
	private long numLocalBytes; // unsigned long
	private long numParamBytes; // unsigned long
	private long maxStackBytes; // unsigned long
	private long frameFunc; // ?  // unsigned long
	private int numPrologBytes; // unsigned short
	private int numSavedRegBytes; // unsigned short
	private boolean hasSEH; // unsigned long bit-field
	private boolean hasEH; // unsigned long bit-field
	private boolean isFunctionStart; // unsigned long bit-field
	private long reserved; // contains shifted/masked remainder of unsigned long

	/**
	 * Returns the RVA start
	 * @return the RVA start
	 */
	public long getRvaStart() {
		return rvaStart;
	}

	/**
	 * Returns the number of bytes in the block (function)
	 * @return the number of bytes in the block
	 */
	public long getNumberBlockBytes() {
		return numBlockBytes;
	}

	/**
	 * Returns the number of bytes used by local variables
	 * @return the number of bytes used by locals
	 */
	public long getNumberLocalBytes() {
		return numLocalBytes;
	}

	/**
	 * Returns the number of bytes used by the parameters
	 * @return the number of bytes used by parameters
	 */
	public long getNumberParameterBytes() {
		return numParamBytes;
	}

	/**
	 * Returns max number of stack bytes
	 * @return max stack bytes
	 */
	public long getMaxStackBytes() {
		return maxStackBytes;
	}

	// TODO: change javadoc and method name and underlying variable once we've determined what
	// this is
	/**
	 * Returns the frame func... not yet sure what this is
	 * @return the frame func
	 */
	public long getFrameFunc() {
		return frameFunc;
	}

	/**
	 * Returns the number of bytes in the function prolog
	 * @return the number of bytes in the prolog
	 */
	public int getNumberFunctionPrologBytes() {
		return numPrologBytes;
	}

	/**
	 * Returns the number of bytes for saved registers
	 * @return the number of bytes used by saved registers
	 */
	public int getNumberSavedRegisterBytes() {
		return numSavedRegBytes;
	}

	/**
	 * Returns whether has SEH
	 * @return {@code true} if has SEH
	 */
	public boolean hasSEH() {
		return hasSEH;
	}

	/**
	 * Returns whether has EH
	 * @return {@code true} if has EH
	 */
	public boolean hasEH() {
		return hasEH;
	}

	/**
	 * Returns whether is function start
	 * @return {@code true} if us function start
	 */
	public boolean isFunctionStart() {
		return isFunctionStart;
	}

	/**
	 * Returns the value of the reserved, remaining 29 bit-field bits
	 * @return the value of the reserved field
	 */
	public long reserved() {
		return reserved;
	}

	public void parse(PdbByteReader reader) throws PdbException {
		if (reader.numRemaining() < 32) {
			throw new PdbException("Not enough data for FrameDataRecord");
		}
		rvaStart = reader.parseUnsignedIntVal();
		numBlockBytes = reader.parseUnsignedIntVal();
		numLocalBytes = reader.parseUnsignedIntVal();
		numParamBytes = reader.parseUnsignedIntVal();
		maxStackBytes = reader.parseUnsignedIntVal();
		frameFunc = reader.parseUnsignedIntVal();
		numPrologBytes = reader.parseUnsignedShortVal();
		numSavedRegBytes = reader.parseUnsignedShortVal();
		reserved = reader.parseUnsignedIntVal();
		hasSEH = (reserved & 0x01) == 0x01;
		reserved >>= 1;
		hasEH = (reserved & 0x01) == 0x01;
		reserved >>= 1;
		isFunctionStart = (reserved & 0x01) == 0x01;
		reserved >>= 1;
		reserved &= 0x01ffffff;
	}

	/**
	 * Dumps the {@link FramePointerOmissionRecord}.  This package-protected method is for
	 *  debugging only.
	 * @param writer {@link Writer} to which to write the debug dump.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	void dump(Writer writer) throws IOException {
		writer.write("FrameDataRecord---------------------------------------------\n");
		writer.write(String.format("rvaStart: 0X%08X\n", rvaStart));
		writer.write(String.format("numBlockBytes: 0X%08X\n", numBlockBytes));
		writer.write(String.format("numLocalBytes: 0X%08X\n", numLocalBytes));
		writer.write(String.format("numParamBytes: 0X%08X\n", numParamBytes));
		writer.write(String.format("maxStackBytes: 0X%08X\n", maxStackBytes));
		writer.write(String.format("frameFunc: 0X%08X\n", frameFunc));
		writer.write(String.format("numPrologBytes: 0X%04X\n", numPrologBytes));
		writer.write(String.format("numSavedRegBytes: 0X%04X\n", numSavedRegBytes));
		writer.write(
			String.format("hasStructuedExceptionHandling: %s\n", Boolean.toString(hasSEH)));
		writer.write(String.format("hasExceptionHandling: %s\n", Boolean.toString(hasEH)));
		writer.write(String.format("isFunctionStart: %s\n", Boolean.toString(isFunctionStart)));
		writer.write("End FrameDataRecord-----------------------------------------\n");
	}
}
