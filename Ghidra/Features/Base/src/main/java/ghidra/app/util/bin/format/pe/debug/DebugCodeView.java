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
package ghidra.app.util.bin.format.pe.debug;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pdb.PdbInfoCodeView;
import ghidra.app.util.bin.format.pdb.PdbInfoDotNet;
import ghidra.app.util.bin.format.pe.OffsetValidator;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the code view debug information.
 */
public class DebugCodeView implements StructConverter {
	private DebugDirectory debugDir;
	private DebugCodeViewSymbolTable symbolTable;
	private PdbInfoCodeView pdbInfo;
	private PdbInfoDotNet dotNetPdbInfo;

	/**
	 * Constructor.
	 * @param reader the binary reader
	 * @param debugDir the code view debug directory
	 * @param ntHeader 
	 */
	static DebugCodeView createDebugCodeView(FactoryBundledWithBinaryReader reader,
			DebugDirectory debugDir, OffsetValidator validator) throws IOException {
		DebugCodeView debugCodeView =
			(DebugCodeView) reader.getFactory().create(DebugCodeView.class);
		debugCodeView.initDebugCodeView(reader, debugDir, validator);
		return debugCodeView;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public DebugCodeView() {
	}

	private void initDebugCodeView(FactoryBundledWithBinaryReader reader, DebugDirectory debugDir,
			OffsetValidator validator) throws IOException {
		this.debugDir = debugDir;

		int ptr = debugDir.getPointerToRawData();
		if (!validator.checkPointer(ptr)) {
			Msg.error(this, "Invalid pointer " + Long.toHexString(ptr));
			return;
		}

		dotNetPdbInfo = PdbInfoDotNet.isMatch(reader, ptr) ? PdbInfoDotNet.read(reader, ptr) : null;
		pdbInfo = PdbInfoCodeView.isMatch(reader, ptr) ? PdbInfoCodeView.read(reader, ptr) : null;
		if (DebugCodeViewSymbolTable.isMatch(reader, ptr)) {
			symbolTable =
				DebugCodeViewSymbolTable.createDebugCodeViewSymbolTable(reader,
					debugDir.getSizeOfData(), debugDir.getPointerToRawData(), ptr);
		}
		else {
			//TODO??
//            Err.warn(this, null, "Warning", "Unhandled CodeView Information Format: "+
//			                        Integer.toHexString(reader.readShort(ptr+0)&0xffff)+
//			                        " "+
//			                        Integer.toHexString(reader.readShort(ptr+1)&0xffff));
		}
	}

	/**
	 * Returns the code view debug directory.
	 * @return the code view debug directory
	 */
	public DebugDirectory getDebugDirectory() {
		return debugDir;
	}

	/**
	 * Returns the code view symbol table.
	 * @return the code view symbol table
	 */
	public DebugCodeViewSymbolTable getSymbolTable() {
		return symbolTable;
	}

	/**
	 * Returns the code view .PDB info.
	 * @return the code view .PDB info
	 */
	public PdbInfoCodeView getPdbInfo() {
		return pdbInfo;
	}

	public PdbInfoDotNet getDotNetPdbInfo() {
		return dotNetPdbInfo;
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() throws DuplicateNameException {
		Structure es = new StructureDataType("DebugCodeView", 0);
		es.add(WORD, "Signature", null);
		es.add(WORD, "Version", null);
		if (symbolTable != null) {
			DataType dt = symbolTable.toDataType();
			es.add(dt, "CodeViewSymbolTable", null);
		}
		else {
			DataType dt = new ArrayDataType(BYTE, debugDir.getSizeOfData() - 4, 1);
			es.add(dt, "<<unknown>>", null);
		}
		es.setCategoryPath(new CategoryPath("/PE"));
		return es;
	}

}
