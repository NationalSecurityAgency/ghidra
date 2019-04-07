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
package ghidra.app.util.bin.format.macho.commands;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.*;

import java.io.*;

public class DynamicLibraryModule implements StructConverter {
    private int module_name;            // the module name (index into string table)
    private int iextdefsym;             // index into externally defined symbols
    private int nextdefsym;             // number of externally defined symbols
    private int irefsym;                // index into reference symbol table
    private int nrefsym;                // number of reference symbol table entries
    private int ilocalsym;              // index into symbols for local symbols
    private int nlocalsym;              // number of local symbols
    private int iextrel;                // index into external relocation entries
    private int nextrel;                // number of external relocation entries
    private int iinit_iterm;            // low 16 bits are the index into the init section, high 16 bits are the index into the term section
    private int ninit_nterm;            // low 16 bits are the number of init section entries, high 16 bits are the number of term section entries
    private int objc_module_info_size;  // for this module size of the (__OBJC,__module_info) section
    private long objc_module_info_addr; // for this module address of the start of the (__OBJC,__module_info) section

    private boolean is32bit;
    private String moduleName;

    public static DynamicLibraryModule createDynamicLibraryModule(
            FactoryBundledWithBinaryReader reader, MachHeader header)
            throws IOException {
        DynamicLibraryModule dynamicLibraryModule = (DynamicLibraryModule) reader.getFactory().create(DynamicLibraryModule.class);
        dynamicLibraryModule.initDynamicLibraryModule(reader, header);
        return dynamicLibraryModule;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public DynamicLibraryModule() {}

	private void initDynamicLibraryModule(FactoryBundledWithBinaryReader reader, MachHeader header) throws IOException {
		this.is32bit = header.is32bit();

		module_name                = reader.readNextInt();
		iextdefsym                 = reader.readNextInt();
		nextdefsym                 = reader.readNextInt();
		irefsym                    = reader.readNextInt();
		nrefsym                    = reader.readNextInt();
		ilocalsym                  = reader.readNextInt();
		nlocalsym                  = reader.readNextInt();
		iextrel                    = reader.readNextInt();
		nextrel                    = reader.readNextInt();
		iinit_iterm                = reader.readNextInt();
		ninit_nterm                = reader.readNextInt();
		if (is32bit) {
			objc_module_info_addr  = reader.readNextInt() & 0xffffffffL;
		    objc_module_info_size  = reader.readNextInt();
		}
		else {
			objc_module_info_size  = reader.readNextInt();
			objc_module_info_addr  = reader.readNextLong();
		}

		SymbolTableCommand stc = header.getFirstLoadCommand(SymbolTableCommand.class);
		moduleName = reader.readAsciiString(stc.getStringTableOffset()+module_name);
	}

	public int getModuleNameIndex() {
		return module_name;
	}
	public String getModuleName() {
		return moduleName;
	}
	public int getExtDefSymIndex() {
		return iextdefsym;
	}
	public int getExtDefSymCount() {
		return nextdefsym;
	}
	public int getReferenceSymbolTableIndex() {
		return irefsym;
	}
	public int getReferenceSymbolTableCount() {
		return nrefsym;
	}
	public int getLocalSymbolIndex() {
		return ilocalsym;
	}
	public int getLocalSymbolCount() {
		return nlocalsym;
	}
	public int getExternalRelocationIndex() {
		return iextrel;
	}
	public int getExternalRelocationCount() {
		return nextrel;
	}
	/**
	 * low 16 bits are the index into the init section, 
	 * high 16 bits are the index into the term section
	 */
	public int getInitTermIndex() {
		return iinit_iterm;
	}
	/**
	 * low 16 bits are the number of init section entries, 
	 * high 16 bits are the number of term section entries
	 * @return
	 */
	public int getInitTermCount() {
		return ninit_nterm;
	}
	public int getObjcModuleInfoSize() {
		return objc_module_info_size;
	}
	public long getObjcModuleInfoAddress() {
		return objc_module_info_addr;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
	    StructureDataType struct = new StructureDataType("dylib_module", 0);
	    struct.add(DWORD, "module_name", "the module name (index into string table)");
	    struct.add(DWORD, "iextdefsym",  "index into externally defined symbols");
	    struct.add(DWORD, "nextdefsym",  "number of externally defined symbols");
	    struct.add(DWORD, "irefsym",     "index into reference symbol table");
	    struct.add(DWORD, "nrefsym",     "number of reference symbol table entries");
	    struct.add(DWORD, "ilocalsym",   "index into symbols for local symbols");
	    struct.add(DWORD, "nlocalsym",   "number of local symbols");
	    struct.add(DWORD, "iextrel",     "index into external relocation entries");
	    struct.add(DWORD, "nextrel",     "number of external relocation entries");
	    struct.add(DWORD, "iinit_iterm", "low 16 bits are the index into the init section, high 16 bits are the index into the term section");
	    struct.add(DWORD, "ninit_nterm", "low 16 bits are the number of init section entries, high 16 bits are the number of term section entries");
	    if (is32bit) {
		    struct.add(DWORD, "objc_module_info_addr", "module size");
		    struct.add(DWORD, "objc_module_info_size", "module start address");
	    }
	    else {
	    	struct.add(DWORD, "objc_module_info_size", "module size");
	    	struct.add(QWORD, "objc_module_info_addr", "module start address");
	    }
	    struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
	    return struct;
	}
}
