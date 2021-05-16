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

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;

public class ElfDataType extends FactoryStructureDataType {
	private final static long serialVersionUID = 1;

    /**
     * Constructs a new ELF datatype.
     */
	public ElfDataType() {
		this(null);
	}
	
	public ElfDataType(DataTypeManager dtm) {
		super("ELF", dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "ELF";
	}

	@Override
    public String getDescription() { 
        return "ELF Data Type";
    }

	@Override
	protected void populateDynamicStructure(MemBuffer buf, Structure struct) {
		try {
	        Memory memory = buf.getMemory();
	        MemoryBlock block = memory.getBlock(buf.getAddress());
	        byte [] bytes = new byte[(int)block.getSize()];
	        block.getBytes(block.getStart(), bytes);

	        ByteArrayProvider bap = new ByteArrayProvider(bytes);

	        ElfHeader elf = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, bap);
	        elf.parse();

	        struct.add(elf.toDataType());
		}
		catch (Exception e) {
			
		}
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		return new ElfDataType(dtm);
	}
	
}
