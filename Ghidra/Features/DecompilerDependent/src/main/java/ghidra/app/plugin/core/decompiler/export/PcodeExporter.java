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
package ghidra.app.plugin.core.decompiler.export;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class PcodeExporter extends BasePcodeExporter {

	public String LANGUAGE = "CTADLLanguage";
	public String PROGRAM_FILE = "PROGRAM_FILE";

	private String REGISTER_OFF_NAME = "REGISTER_OFF_NAME";
	private String REGISTER_IS_SP = "REGISTER_IS_SP";
	private String SPACE_OFFSET = "SPACE_OFFSET";
	private String DATA_STRING = "DATA_STRING";
	private String FUNC_ISEXT = "FUNC_ISEXT";
	private String FUNC_PARAMETER = "FUNC_PARAMETER";
	private String FUNC_PARAMETER_COUNT = "FUNC_PARAMETER_COUNT";
	private String FUNC_PARAMETER_DATATYPE = "FUNC_PARAMETER_DATATYPE";
	private String MNEMONICS = "MNEMONICS";
	private String TABLE = "TABLE";

	private final Set<String> types = new HashSet<String>();
	private final Set<Address> vtables = new HashSet<Address>();

	public PcodeExporter(String directory) throws IOException {
		super(directory);
	}

	public void exportRegisterInfo(Program program) {
		Language language = program.getLanguage();
		CompilerSpec cSpec = program.getCompilerSpec();
		Register sp = cSpec.getStackPointer();

		for (Register reg : language.getRegisters()) {
			if (reg.getAddress().isRegisterAddress()) {
				db.addExport(REGISTER_OFF_NAME, Long.toString(reg.getAddress().getOffset()),
					Integer.toString(reg.getMinimumByteSize()), reg.getName());
				if (sp != null && (sp.equals(reg) || sp.contains(reg))) {
					db.addExport(REGISTER_IS_SP, reg.getName());
				}
			}
		}
	}

	public void exportMnemonics(Program program) {
		for (OpCode op : OpCode.values()) {
			export(MNEMONICS, Integer.toString(op.ordinal()), op.getName());
		}
	}

	public void exportAddressSpaces(Program program) {
		for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
			export(SPACE_OFFSET, space.getName(),
				Integer.toString(space.getSpaceID()));
		}
	}

	public void exportDefinedData(Program p) {
		DataIterator dataIter = p.getListing().getDefinedData(p.getMinAddress(), true);
		for (Data d : dataIter) {
			if (!isString(d.getMnemonicString()))
				continue;
			Address addr = d.getAddress();
			export(DATA_STRING, addressString(addr), d.getValue().toString());
		}
	}

	public void externalFunctionParameters(Program currentProgram) {
		currentProgram.getFunctionManager().getFunctions(true).forEach(f -> {
			db.addExport(FUNC_PARAMETER_COUNT, f.getName(),
				Integer.toString(f.getParameterCount()));
			for (Parameter p : f.getParameters()) {
				db.addExport(FUNC_PARAMETER, f.getName(), Integer.toString(p.getOrdinal()),
					p.getName());
				db.addExport(FUNC_PARAMETER_DATATYPE, f.getName(),
					Integer.toString(p.getOrdinal()), dtID(p.getDataType()));
			}
		});
		currentProgram.getFunctionManager().getExternalFunctions().forEach(f -> {
			db.addExport(FUNC_ISEXT, f.getName());
			db.addExport(FUNC_PARAMETER_COUNT, f.getName(),
				Integer.toString(f.getParameterCount()));
			for (Parameter p : f.getParameters()) {
				db.addExport(FUNC_PARAMETER, f.getName(), Integer.toString(p.getOrdinal()),
					p.getName());
				db.addExport(FUNC_PARAMETER_DATATYPE, f.getName(),
					Integer.toString(p.getOrdinal()), dtID(p.getDataType()));
			}
		});
	}

	private void exportType(DataType dataType) {
		String id = dtID(dataType);
		if (!types.add(id))
			return;

		export("TYPE_NAME", id, id);
		export("TYPE_LENGTH", id, Integer.toString(dataType.getLength()));
		while (dataType instanceof TypeDef) {
			TypeDef typedef = (TypeDef) dataType;
			dataType = typedef.getBaseDataType();
		}
		if (dataType instanceof Pointer) {
			export("TYPE_TYPE", id, "pointer");
			DataType baseType = ((Pointer) dataType).getDataType();
			if (baseType != null) {
				export("TYPE_POINTER_BASE", id, dtID(baseType));
				exportType(baseType);
			}
		}
		if (dataType instanceof Array arr) {
			export("TYPE_TYPE", id, "array");
			export("TYPE_ARRAY_BASE", id, dtID(arr.getDataType()));
			export("TYPE_ARRAY_N", id, Integer.toString(arr.getNumElements()));
			export("TYPE_ARRAY_ELEMENT_LENGTH", id, Integer.toString(arr.getElementLength()));
			exportType(arr.getDataType());
		}
		if (dataType instanceof Structure struct) {
			export("TYPE_TYPE", id, "struct");
			export("TYPE_STRUCT_FIELD_COUNT", id, Integer.toString(struct.getNumComponents()));
			for (int i = 0; i < struct.getNumComponents(); i++) {
				DataTypeComponent dtc = struct.getComponent(i);
				exportComponent("TYPE_STRUCT", id, i, dtc);
			}
		}
		if (dataType instanceof Union union) {
			export("TYPE_TYPE", id, "union");
			export("TYPE_UNION_FIELD_COUNT", id, Integer.toString(union.getNumComponents()));
			for (int i = 0; i < union.getNumComponents(); i++) {
				DataTypeComponent dtc = union.getComponent(i);
				exportComponent("TYPE_UNION", id, i, dtc);
			}
		}
		if (dataType instanceof FunctionDefinition fd) {
			export("TYPE_TYPE", id, "function");
			export("TYPE_FUNC_RET", id, fd.getReturnType().toString());
			exportType(fd.getReturnType());
			if (fd.hasVarArgs()) {
				export("TYPE_FUNC_VARARGS", id, id);
			}
			ParameterDefinition[] arguments = fd.getArguments();
			export("TYPE_FUNC_PARAM_COUNT", id,  Integer.toString(arguments.length));
			for (int i = 0; i < arguments.length; i++) {
				export("TYPE_FUNC_PARAM", id, arguments[i] + ":" + i);
				exportType(arguments[i].getDataType());
			}
		}
		if (dataType instanceof BooleanDataType) {
			export("TYPE_TYPE", id, "boolean");
		}
		if (dataType instanceof AbstractIntegerDataType) {
			export("TYPE_TYPE", id, "integer");
		}
		if (dataType instanceof AbstractFloatDataType) {
			export("TYPE_TYPE", id, "float");
		}
		if (dataType instanceof Enum) {
			export("TYPE_TYPE", id, "enum");
		}
	}

	private void exportComponent(String label, String id, int i, DataTypeComponent dtc) {
		String dtcid = dtID(dtc.getDataType());
		export(label + "_FIELD", id, dtcid + ":" + i);
		export(label + "_OFFSET", id, dtc.getOffset() + ":" + i);
		export(label + "_OFFSET_N", id, dtc.getOffset() + ":" + i);
		if (dtc.getFieldName() != null && !dtc.getFieldName().isEmpty()) {
			export(label + "_FIELD_NAME", id, dtc.getFieldName() + ":" + i);
			//export(label + "_FIELD_NAME_BY_OFFSET", id, dtc.getOffset(),
			//	dtc.getFieldName() + ":" + i);
		}
		exportType(dtc.getDataType());
	}

	private String dtID(DataType dt) {
		if (dt.getName() != null) {
			return dt.getName().replaceAll(" ", "");
		}
		return dt.toString();
	}

	public void processVTable(Program program, Symbol sym) {
		StringBuilder className = new StringBuilder();
		for (String s : sym.getPath()) {
			className.append("::" + s);
		}
		Address addr = sym.getAddress();
		if (program.getMemory().getBlock(addr).isExternalBlock())
			return;
		// SymbolTable symbolTable = program.getSymbolTable();
		AddressFactory addrFactory = program.getAddressFactory();
		int ptrBytes = program.getAddressFactory().getDefaultAddressSpace().getSize() / 8;

		// Skip first two addresses to get to function pointer table
		// BigInteger classOffset = readInteger(program, addr, ptrBytes);
		addr = addr.add(ptrBytes);
		// BigInteger typeInfo = readInteger(program, addr, ptrBytes);
		addr = addr.add(ptrBytes);
		Address tableAddr = addr;

		// Reads function pointer table
		int funOffset = 0;
		BigInteger funPtrInt;
		Address funPtrAddr;
		while (true) {
			// Breaks if we hit another vtable
			if (vtables.contains(addr)) {
				break;
			}

			// read next function pointer
			funPtrInt = readInteger(program, addr, ptrBytes);
			funPtrAddr = addrFactory.getAddress(addrFactory.getDefaultAddressSpace().getSpaceID(),
				funPtrInt.longValue());

			// The table ends when one of three things is true:
			// 1. Reading a zero
			if (funPtrInt == BigInteger.ZERO) {
				break;
			}

			// 2. If there are defined symbols, we are out of the vtable, so break
			// if (symbolTable.getSymbols(funPtrAddr).length > 0)
			// break;

			// emit fact
			db.addExport(TABLE, className.toString(), addressString(tableAddr),
				Integer.toString(funOffset * ptrBytes), funPtrInt.toString());
			//
			// 3. if next block is different from ours, break
			MemoryBlock blockPred = program.getMemory().getBlock(funPtrAddr);
			MemoryBlock blockSucc = program.getMemory().getBlock(funPtrAddr.add(ptrBytes));
			if (!Objects.equals(blockPred, blockSucc)) {
				break;
			}

			addr = addr.add(ptrBytes);
			funOffset++;
		}
	}

	public void processVTables(Program program) {
		SymbolIterator vtableSymbols = program.getSymbolTable().getSymbols("vtable");
		while (vtableSymbols.hasNext()) {
			Symbol sym = vtableSymbols.next();
			processVTable(program, sym);
		}
	}

	private BigInteger readInteger(Program program, Address addr, int size) {
		//AddressFactory addrFactory = program.getAddressFactory();
		//int spaceID = addr.getAddressSpace().getSpaceID();
		try {
			byte[] dest = new byte[size];
			program.getMemory().getBytes(addr, dest, 0, size);
			if (!program.getLanguage().isBigEndian()) {
				ArrayUtils.reverse(dest);
			}
			return new BigInteger(dest);
		}
		catch (MemoryAccessException e) {
			debug("MemoryAccessException, skipping: " + e);
			return BigInteger.ZERO;
		}
	}

	private String addressString(Address addr) {
		return Long.toString(addr.getOffset());
	}

	boolean isString(String mnemonic) {
		return switch (mnemonic) {
			case "ds" -> true;
			case "unicode" -> true;
			case "p_unicode" -> true;
			case "p_string" -> true;
			case "p_string255" -> true;
			case "mbcs" -> true;
			default -> false;
		};
	}

}
