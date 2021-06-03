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
package ghidra.app.util.opinion;

import java.io.IOException;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * A datatype for creating portable executable data structures.
 */
public class PeDataType extends FactoryStructureDataType {

    /**
     * Constructs a new PE datatype.
     */
	public PeDataType() {
		this(null);
	}
	
	public PeDataType(DataTypeManager dtm) {
		super("PE", dtm);
	}

    @Override
	public String getMnemonic(Settings settings) {
        return "PE";
    }

    @Override
    public String getDescription() { 
        return "Windows Portable Executable Data Type";
    }

    @Override
	protected void populateDynamicStructure(MemBuffer buf, Structure struct) {
		try {
			Memory memory = buf.getMemory();
			MemoryBlock block = memory.getBlock(buf.getAddress());

			int size = Math.min(0x100000, (int) block.getEnd().subtract(buf.getAddress()) + 1);//only request 1MB, at most (should never need more)

			byte[] bytes = new byte[size];
			block.getBytes(buf.getAddress(), bytes);

			ByteArrayProvider bap = new ByteArrayProvider(bytes);

			PortableExecutable pe = PortableExecutable.createPortableExecutable(
				RethrowContinuesFactory.INSTANCE, bap, SectionLayout.FILE);

			DOSHeader dosHeader = pe.getDOSHeader();
			addComponent(struct, dosHeader.toDataType(), DOSHeader.NAME);

			NTHeader ntHeader = pe.getNTHeader();
			if (ntHeader == null) {
				return;
			}

			addComponent(struct, ntHeader.toDataType(), ntHeader.getName());

			SectionHeader[] sections = ntHeader.getFileHeader().getSectionHeaders();
			for (SectionHeader section : sections) {
				addComponent(struct, section.toDataType(), section.getReadableName());
			}
		}
		catch (IOException e) {
		}
		catch (MemoryAccessException e) {
		}
		catch (DuplicateNameException e) {
		}
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		return new PeDataType(dtm);
	}

}
