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
package ghidra.app.util.pdb;

import java.util.*;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.pdb.classtype.MsVxtManager;
import ghidra.app.util.pdb.pdbapplicator.CppCompositeType;
import ghidra.app.util.pdb.pdbapplicator.ObjectOrientedClassLayout;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Mock PDB for testing
 */
public class MockPdb {
	private Set<DataType> types;
	private Set<CppCompositeType> cppTypes;
	private Map<Address, DataType> typesByAddress;
	private Map<Address, Set<SymbolPath>> symbolsByAddress;

	private Map<DataType, DataType> resolvedMap;

	public MockPdb() {
		types = new LinkedHashSet<>();
		cppTypes = new LinkedHashSet<>();
		typesByAddress = new TreeMap<>();
		symbolsByAddress = new TreeMap<>();

		resolvedMap = new HashMap<>();
	}

	public void addSymbol(Address addr, String name) {
		Set<SymbolPath> symbols = symbolsByAddress.get(addr);
		if (symbols == null) {
			symbols = new LinkedHashSet<>();
			symbolsByAddress.put(addr, symbols);
		}
		SymbolPath symbol = new SymbolPath(SymbolPathParser.parse(name));
		symbols.add(symbol);
	}

	/**
	 * Method to add a type.  User should add types in dependency order, starting with leaves
	 * @param type the type to add
	 */
	public void addType(DataType type) {
		types.add(type);
	}

	public void addType(CppCompositeType type) {
		cppTypes.add(type);
	}

	public void applyAll(Program program, DataTypeManager dtm,
			ObjectOrientedClassLayout layoutOptions, MsVxtManager vxtManager, TaskMonitor monitor)
			throws CancelledException, PdbException {
		resolveRegularTypes(dtm);
		applyCppTypes(layoutOptions, vxtManager, monitor);
		resolveCppTypes(dtm);
		if (program != null) {
			placeTypes(program);
			applySymbols(program);
		}
	}

	public Set<CppCompositeType> getCppTypes() {
		return cppTypes;
	}

	public void applyCppTypes(ObjectOrientedClassLayout layoutOptions, MsVxtManager vxtManager,
			TaskMonitor monitor)
			throws PdbException, CancelledException {
		for (CppCompositeType type : cppTypes) {
			type.createLayout(layoutOptions, vxtManager, monitor);
		}
	}

	public void applyCppType(CppCompositeType type, ObjectOrientedClassLayout layoutOptions,
			MsVxtManager vxtManager, TaskMonitor monitor)
			throws PdbException, CancelledException {
		type.createLayout(layoutOptions, vxtManager, monitor);
	}

	/**
	 * Method to resolve all regular types
	 * @param dtm the data type manager
	 */
	private void resolveRegularTypes(DataTypeManager dtm) {
		for (DataType type : types) {
			DataType resolved = dtm.resolve(type, null);
			resolvedMap.put(type, resolved);
		}
	}

	/**
	 * Method to resolve all CppTypes types
	 * @param dtm the data type manager
	 */
	public void resolveCppTypes(DataTypeManager dtm) {
		for (CppCompositeType cppType : cppTypes) {
			resolveType(dtm, cppType);
		}
	}

	public Composite resolveType(DataTypeManager dtm, CppCompositeType cppType) {
		Composite type = cppType.getComposite();
		Composite resolved = (Composite) dtm.resolve(type, null);
		resolvedMap.put(type, resolved);
		return resolved;
	}

	private void placeTypes(Program program) {
		for (Map.Entry<Address, DataType> entry : typesByAddress.entrySet()) {
			Address addr = entry.getKey();
			DataType resolvedType = resolvedMap.get(entry.getValue());
			placeType(program, addr, resolvedType);
		}
	}

	private void placeType(Program program, Address addr, DataType type) {
		DumbMemBufferImpl memBuffer =
			new DumbMemBufferImpl(program.getMemory(), addr);
		DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(type, memBuffer, false);
		if (dti == null) {
			Msg.warn(MockPdb.class,
				"Error: Failed to apply datatype " + type.getName() + " at " + addr);
			return;
		}
		DataType dt = dti.getDataType();
		int length = dti.getLength();

		try {
			program.getListing().clearCodeUnits(addr, addr.add(length - 1), false);
			if (dt.getLength() == -1) {
				program.getListing().createData(addr, dt, length);
			}
			else {
				program.getListing().createData(addr, dt);
			}
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(MockPdb.class, "Unable to create " + dt.getDisplayName() + " at 0x" +
				addr + ": " + e.getMessage());
		}
	}

	public void applySymbols(Program program) {
		for (Map.Entry<Address, Set<SymbolPath>> entry : symbolsByAddress.entrySet()) {
			Address addr = entry.getKey();
			for (SymbolPath sp : entry.getValue()) {
				applySymbol(program, addr, sp, false);
			}
		}
	}

	public Symbol applySymbol(Program program, Address address, SymbolPath symbolPath,
			boolean makePrimary) {
		Symbol symbol = null;
		try {
			Namespace namespace = program.getGlobalNamespace();
			String name = symbolPath.getName();
			String namespacePath = symbolPath.getParentPath();
			if (namespacePath != null) {
				namespace = NamespaceUtils.createNamespaceHierarchy(namespacePath, namespace,
					program, address, SourceType.IMPORTED);
			}
			symbol =
				program.getSymbolTable().createLabel(address, name, namespace, SourceType.IMPORTED);
			if (makePrimary && !symbol.isPrimary()) {
				SetLabelPrimaryCmd cmd =
					new SetLabelPrimaryCmd(address, symbol.getName(),
						symbol.getParentNamespace());
				cmd.applyTo(program);
			}
		}
		catch (InvalidInputException e) {
			Msg.warn(MockPdb.class,
				"Unable to create symbol at " + address + " due to exception: " +
					e.toString() + "; symbolPathName: " + symbolPath);
		}
		return symbol;
	}
}
