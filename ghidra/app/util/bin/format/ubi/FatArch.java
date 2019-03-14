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
package ghidra.app.util.bin.format.ubi;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.CpuSubTypes;
import ghidra.app.util.bin.format.macho.CpuTypes;

/**
 * Represents a fat_arch structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/fat.h.auto.html">mach-o/fat.h</a> 
 */
public class FatArch {
    private int cputype;
	private int cpusubtype;
	private int offset;
	private int size;
	private int align;

    public static FatArch createFatArch(FactoryBundledWithBinaryReader reader)
            throws IOException {
        FatArch fatArch = (FatArch) reader.getFactory().create(FatArch.class);
        fatArch.initFatArch(reader);
        return fatArch;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public FatArch() {}

    private void initFatArch(FactoryBundledWithBinaryReader reader) throws IOException {
		cputype    = reader.readNextInt();
		cpusubtype = reader.readNextInt();
		offset     = reader.readNextInt();
		size       = reader.readNextInt();
		align      = reader.readNextInt();
	}

	/**
	 * @see CpuTypes
	 */
	public int getCpuType() {
		return cputype;
	}
	/**
	 * @see CpuSubTypes
	 */
	public int getCpuSubType() {
		return cpusubtype;
	}
	/**
	 * Returns the file offset to this object file.
	 * @return the file offset to this object file
	 */
	public int getOffset() {
		return offset;
	}
	/**
	 * Returns the size of this object file.
	 * @return the size of this object file
	 */
	public int getSize() {
		return size;
	}
	/**
	 * Returns the alignment as a power of 2.
	 * @return the alignment as a power of 2
	 */
	public int getAlign() {
		return align;
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("CPU Type: 0x" + Integer.toHexString(cputype));
		buffer.append('\n');
		buffer.append("CPU Sub Type: 0x" + Integer.toHexString(cpusubtype));
		buffer.append('\n');
		buffer.append("Offset: 0x" + Integer.toHexString(offset));
		buffer.append('\n');
		buffer.append("Size: 0x" + Integer.toHexString(size));
		buffer.append('\n');
		buffer.append("Align: 0x" + Integer.toHexString(align));
		buffer.append('\n');
		return buffer.toString();
	}
}
