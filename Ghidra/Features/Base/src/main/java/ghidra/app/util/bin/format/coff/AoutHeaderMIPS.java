/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.coff;

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

public class AoutHeaderMIPS extends AoutHeader {
	public final static int SIZEOF = 56;

	private int      bss_start; // base of bss used for this file
	private int      gprmask;   // general purpose register mask
	private int  []  cprmask;   // co-processor  register mask
	private int      gp_value;  // the gp value used for this object

	AoutHeaderMIPS(BinaryReader reader) throws IOException {
		super(reader);

		bss_start   = reader.readNextInt();
		gprmask     = reader.readNextInt();
		cprmask     = reader.readNextIntArray(4);
		gp_value    = reader.readNextInt();
	}

	public int getUnitializedDataStart() {
		return bss_start;
	}

	/**
	 * Returns the general purpose register mask.
	 * @return the general purpose register mask
	 */
	public int getGprMask() {
		return gprmask;
	}

	/**
	 * Returns the co-processor register masks.
	 * @return the co-processor register masks
	 */
	public int [] getCprMask() {
		return cprmask;
	}

	/**
	 * Returns the GP value.
	 * @return the GP value
	 */
	public int getGpValue() {
		return gp_value;
	}
}
