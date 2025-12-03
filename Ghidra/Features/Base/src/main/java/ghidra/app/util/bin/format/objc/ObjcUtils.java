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
package ghidra.app.util.bin.format.objc;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.Command;
import ghidra.program.database.symbol.ClassSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class ObjcUtils {

	/**
	 * {@return the next read index value}
	 * <p>
	 * If {@code is32bit} is true, then 4 bytes will be read to form the index. Otherwise, 8 bytes
	 * will be read to form the index.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the index to read
	 * @param is32bit True if the index is 32-bit; false if 64-bit;
	 * @throws IOException if an IO-related error occurred
	 */
	public static long readNextIndex(BinaryReader reader, boolean is32bit) throws IOException {
		return is32bit ? reader.readNextUnsignedInt() : reader.readNextLong();
	}

	/**
	 * {@return the string referenced at the next read pointer, or {@code null} if the pointer is
	 * 0}
	 * <p>
	 * If {@code is32bit} is true, then 4 bytes will be read to form the pointer. Otherwise, 8 bytes
	 * will be read to form the pointer.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the string pointer to read
	 * @param is32bit True if the string pointer is 32-bit; false if 64-bit;
	 * @throws IOException if an IO-related error occurred
	 */
	public static String dereferenceAsciiString(BinaryReader reader, boolean is32bit)
			throws IOException {
		long stringIndex = readNextIndex(reader, is32bit);
		return stringIndex != 0 ? reader.readAsciiString(stringIndex) : null;
	}

	/**
	 * {@return whether or not the given address is THUMB code}
	 * 
	 * @param program The {@link Program}
	 * @param address The {@link Address} to check
	 */
	public static boolean isThumb(Program program, Address address) {
		Processor ARM = Processor.findOrPossiblyCreateProcessor("ARM");
		if (program.getLanguage().getProcessor().equals(ARM)) {
			MemoryBlock block = program.getMemory().getBlock(address);
			if (block != null && block.isExecute()) {
				return (address.getOffset() % 2) != 0;
			}
		}
		return false;
	}

	/**
	 * {@return whether or not the given address is THUMB code}
	 * 
	 * @param program The {@link Program}
	 * @param address The address to check
	 */
	public static boolean isThumb(Program program, long address) {
		return isThumb(program, toAddress(program, address));
	}

	/**
	 * If needed, sets the TMode bit at the specified address
	 * 
	 * @param program The {@link Program}
	 * @param state The {@link ObjcState state}
	 * @param address The {@link Address} to set
	 */
	public static void setThumbBit(Program program, ObjcState state, Address address) {
		if (state.thumbCodeLocations.contains(address)) {
			Register tmodeRegister = program.getLanguage().getRegister("TMode");
			if (tmodeRegister != null) {
				Command<Program> c =
					new SetRegisterCmd(tmodeRegister, address, address, BigInteger.valueOf(1));
				c.applyTo(program);
			}
		}
	}

	/**
	 * {@return an {@link Address} that corresponds to the given offset in the default address 
	 * space}
	 * 
	 * @param program The {@link Program}
	 * @param offset The offset to convert to an {@link Address}
	 */
	public static Address toAddress(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Applies the data type at the specified address
	 * 
	 * @param program The {@link Program}
	 * @param dt The {@link DataType} to apply
	 * @param address The {@link Address} to apply the data type at
	 * @throws CodeUnitInsertionException if data creation failed
	 */
	public static void createData(Program program, DataType dt, Address address)
			throws CodeUnitInsertionException {
		Data data = program.getListing().getDefinedDataAt(address);
		if (data != null && data.getDataType().isEquivalent(dt)) {
			return;
		}

		// Clear possible pointers created on import from following pointer chains
		DataUtilities.createData(program, address, dt, -1,
			ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
	}

	/**
	 * Creates a string data type at the given address
	 * 
	 * @param program The {@link Program}
	 * @param address The {@link Address} where to create the string at
	 * @return The string, or {@code null} if it didn't get created
	 */
	public static String createString(Program program, Address address) {
		Data data = program.getListing().getDataAt(address);
		if (data == null) {
			CreateDataCmd cmd = new CreateDataCmd(address, new StringDataType());
			cmd.applyTo(program);
			data = program.getListing().getDefinedDataAt(address);
		}
		if (data == null) {
			return null;
		}
		Object object = data.getValue();
		if (object instanceof String str) {
			return str;
		}
		Msg.error(null, "Unable to locate string at " + address);
		return null; // error condition, a string should exist here
	}

	/**
	 * {@return the namespace inside the given parent namespace, or a newly created one if it
	 * doesn't exist}
	 * 
	 * @param program The {@link Program}
	 * @param parentNamespace The parent namespace
	 * @param namespaceName The name of the namespace to get/create
	 * @throws DuplicateNameException if another label exists with the given name
	 * @throws InvalidInputException if the given name is invalid
	 */
	private static Namespace getNamespace(Program program, Namespace parentNamespace,
			String namespaceName) throws DuplicateNameException, InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace namespace = symbolTable.getNamespace(namespaceName, parentNamespace);
		if (namespace != null) {
			return namespace;
		}
		return symbolTable.createNameSpace(parentNamespace, namespaceName, SourceType.IMPORTED);
	}

	/**
	 * {@return the class inside the given parent namespace, or a newly created one if it
	 * doesn't exist}
	 * 
	 * @param program The {@link Program}
	 * @param parentNamespace The parent namespace
	 * @param namespaceName The name of the class namespace to get/create
	 * @throws DuplicateNameException if another label exists with the given name
	 * @throws InvalidInputException if the given name is invalid
	 */
	public static Namespace getClassNamespace(Program program, Namespace parentNamespace,
			String namespaceName) throws DuplicateNameException, InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol = symbolTable.getClassSymbol(namespaceName, parentNamespace);
		if (symbol instanceof ClassSymbol clsSymbol) {
			if (clsSymbol.getName().equals(namespaceName)) {
				return clsSymbol.getObject();
			}
		}
		return symbolTable.createClass(parentNamespace, namespaceName, SourceType.IMPORTED);
	}

	/**
	 * {@return a newly created primary {@link Symbol}}
	 *
	 * @param program The {@link Program}
	 * @param parentNamespace The parent namespace
	 * @param symbolName The symbol name
	 * @param symbolAddress The symbol {@link Address}
	 * @throws InvalidInputException if the given name is invalid
	 */
	public static Symbol createSymbol(Program program, Namespace parentNamespace, String symbolName,
			Address symbolAddress) throws InvalidInputException {
		Symbol symbol = program.getSymbolTable()
				.createLabel(symbolAddress, symbolName, parentNamespace, SourceType.IMPORTED);
		symbol.setPrimary();
		return symbol;
	}

	/**
	 * {@return a newly created namespace hierarchy formed from the list of given strings}
	 * 
	 * @param program The {@link Program}
	 * @param namespacePath The namespace path
	 * @throws DuplicateNameException if another label exists with the given name
	 * @throws InvalidInputException if the given name is invalid
	 */
	public static Namespace createNamespace(Program program, String... namespacePath)
			throws DuplicateNameException, InvalidInputException {
		Namespace parentNamespace = program.getGlobalNamespace();
		Namespace namespace = null;
		for (String namespaceName : namespacePath) {
			namespace = getNamespace(program, parentNamespace, namespaceName);
			parentNamespace = namespace;
		}
		return namespace;
	}

	/**
	 * Creates methods
	 * 
	 * @param program The {@link Program}
	 * @param state The {@link ObjcState state}
	 * @param log The {@link MessageLog log}
	 * @param monitor A cancellable monitor
	 */
	public final static void createMethods(Program program, ObjcState state, MessageLog log,
			TaskMonitor monitor) {
		monitor.initialize(state.methodMap.size(), "Creating Objective-C Methods...");

		Set<Address> addresses = state.methodMap.keySet();
		for (Address address : addresses) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress();

			ObjcUtils.setThumbBit(program, state, address);

			BackgroundCommand<Program> command = null;

			command = new DisassembleCommand(address, null, true);
			command.applyTo(program, monitor);

			command = new CreateFunctionCmd(address);
			command.applyTo(program, monitor);

			//command = new FunctionStackAnalysisCmd(address, false);
			//command.applyTo(state.program, state.monitor);

			ObjcMethod method = state.methodMap.get(address);

			try {
				state.encodings.processMethodSignature(program, address, method.getTypes(),
					method.getMethodType());
			}
			catch (Exception e) {
				Msg.error(ObjcUtils.class, "Unhandled method signature: " + e.getMessage(), e);
			}
		}
	}

	/**
	 * Removes references to the NULL address and adjusts THUMB references to no longer be offcut
	 * 
	 * @param sectionNames The names of the sections to fix
	 * @param program The {@link Program}
	 * @param monitor A cancellable monitor
	 */
	public final static void fixupReferences(List<String> sectionNames, Program program,
			TaskMonitor monitor) {

		AddressSet addressSet = new AddressSet();

		sectionNames.stream()
				.map(program.getMemory()::getBlock)
				.filter(Objects::nonNull)
				.forEach(b -> addressSet.addRange(b.getStart(), b.getEnd()));

		monitor.initialize(addressSet.getNumAddresses(), "Fixing References...");
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator referenceIterator =
			referenceManager.getReferenceSourceIterator(addressSet, true);
		while (referenceIterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress();
			Address sourceAddress = referenceIterator.next();
			Reference[] references = referenceManager.getReferencesFrom(sourceAddress);
			for (Reference reference : references) {
				if (monitor.isCancelled()) {
					break;
				}
				if (reference.getToAddress().getOffset() == 0x0) {
					referenceManager.delete(reference);
				}
				if (ObjcUtils.isThumb(program, reference.getToAddress())) {
					referenceManager.delete(reference);
					referenceManager.addMemoryReference(reference.getFromAddress(),
						reference.getToAddress().subtract(1), reference.getReferenceType(),
						reference.getSource(), reference.getOperandIndex());
				}
			}
		}
	}

	/**
	 * Sets the given block names as read-only
	 * 
	 * @param memory The {@link Memory}
	 * @param blockNames A {@link List} of block names to set as read-only
	 */
	public static void setBlocksReadOnly(Memory memory, List<String> blockNames) {
		blockNames.stream()
				.map(n -> memory.getBlock(n))
				.filter(Objects::nonNull)
				.forEach(b -> b.setWrite(false));
	}

	/**
	 * {@return a {@link List} of {@link MemoryBlock}s that match the given section name}
	 * 
	 * @param section The section name
	 * @param program The {@link Program}
	 */
	public static List<MemoryBlock> getObjcBlocks(String section, Program program) {
		return Arrays.stream(program.getMemory().getBlocks())
				.filter(b -> b.getName().equals(section))
				.toList();
	}
}
