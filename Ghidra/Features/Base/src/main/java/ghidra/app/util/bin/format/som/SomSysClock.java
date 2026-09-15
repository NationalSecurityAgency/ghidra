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
package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code sys_clock} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomSysClock implements StructConverter {

	/** The size in bytes of a {@link SomSysClock} */
	public static final int SIZE = 0x8;

	private long seconds;
	private long nano;

	/**
	 * Creates a new {@link SomSysClock}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the value
	 * @throws IOException if there was an IO-related error
	 */
	public SomSysClock(BinaryReader reader) throws IOException {
		seconds = reader.readNextUnsignedInt();
		nano = reader.readNextUnsignedInt();
	}

	/**
	 * {@return the number of seconds that have elapsed since January 1, 1970 (at 0:00 GMT)}
	 */
	public long getSeconds() {
		return seconds;
	}

	/**
	 * {@return the nano second of the second (which requires 30 bits to represent)}
	 */
	public long getNanoSeconds() {
		return nano;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("sys_clock", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "seconds", null);
		struct.add(DWORD, "nano", null);
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
