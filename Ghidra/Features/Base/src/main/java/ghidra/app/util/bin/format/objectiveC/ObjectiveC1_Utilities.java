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
package ghidra.app.util.bin.format.objectiveC;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.objc2.ObjectiveC2_InstanceVariable;
import ghidra.app.util.bin.format.objc2.ObjectiveC2_State;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.Command;
import ghidra.program.database.symbol.ClassSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public final class ObjectiveC1_Utilities {

	/**
	 * Clears the code units defined in the given memory block.
	 */
	public static void clear(ObjectiveC2_State state, MemoryBlock block) throws Exception {
		state.program.getListing().clearCodeUnits(block.getStart(), block.getEnd(), false,
			state.monitor);
	}

	/**
	 * Reads the next index value. If is32bit is true, then 4 bytes
	 * will be read to form index. Otherwise, 8 bytes will be read to form index.
	 */
	public static long readNextIndex(BinaryReader reader, boolean is32bit) throws IOException {
		if (is32bit) {
			return reader.readNextInt() & Conv.INT_MASK;
		}
		return reader.readNextLong();
	}

	/**
	 * Dereferences a string pointer and returns the string.
	 * If 32-bit only reads a 32-bit pointer.
	 */
	public static String dereferenceAsciiString(BinaryReader reader, boolean is32bit)
			throws IOException {
		if (is32bit) {
			int stringIndex = reader.readNextInt();
			if (stringIndex != 0) {
				return reader.readAsciiString(stringIndex);
			}
			return null;
		}
		long stringIndex = reader.readNextLong();
		if (stringIndex != 0) {
			return reader.readAsciiString(stringIndex);
		}
		return null;
	}

	/**
	 * Returns true if the given address is zero.
	 */
	public static boolean isNull(Address address) {
		return address.getOffset() == 0x0;
	}

	/**
	 * Returns true if the address is THUMB code.
	 */
	public static boolean isThumb(Program program, Address address) {
		Processor ARM = Processor.findOrPossiblyCreateProcessor("ARM");
		if (program.getLanguage().getProcessor().equals(ARM)) {
			Memory memory = program.getMemory();
			MemoryBlock block = memory.getBlock(address);
			if (block != null && block.isExecute()) {
				return (address.getOffset() % 2) != 0;
			}
		}
		return false;
	}

	/**
	 * Returns true if the address is THUMB code.
	 */
	public static boolean isThumb(Program program, long address) {
		return isThumb(program,
			program.getAddressFactory().getDefaultAddressSpace().getAddress(address));
	}

	/**
	 * If needed, sets the TMode bit at the specified address.
	 */
	public static void setThumbBit(ObjectiveC1_State state, Address address) {
		if (state.thumbCodeLocations.contains(address)) {
			Register tmodeRegister = state.program.getLanguage().getRegister("TMode");
			if (tmodeRegister != null) {
				Command c =
					new SetRegisterCmd(tmodeRegister, address, address, BigInteger.valueOf(1));
				c.applyTo(state.program);
			}
		}
	}

	/**
	 * Manufactures an address from the given long.
	 */
	public static Address toAddress(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Applies the data type at the specified address.
	 */
	public static void applyData(Program program, DataType dt, Address address)
			throws CodeUnitInsertionException, DataTypeConflictException {
		Data data = program.getListing().getDefinedDataAt(address);
		if (data != null && data.getDataType().isEquivalent(dt)) {
			return;
		}
		//program.getListing().clearCodeUnits(address, address.add(dt.getLength()-1));

		program.getListing().createData(address, dt);
	}

	/**
	 * Applies a string data type at the specified address and returns the string object.
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
		if (object instanceof String) {
			return (String) object;
		}
		Msg.error(null, "Unable to locate string at " + address);
		return null;//error condition, a string should exist here
	}

	/**
	 * Applies a pointer data type at the specified address and returns the address being referenced.
	 */
	public static Address createPointerAndReturnAddressBeingReferenced(Program program,
			Address address) throws CodeUnitInsertionException, DataTypeConflictException {
		program.getListing().createData(address, new PointerDataType());
		Data data = program.getListing().getDefinedDataAt(address);
		return (Address) data.getValue();
	}

	/**
	 * Applies a pointer data type at the specified address and returns the newly created data object.
	 */
	public static Data createPointer(Program program, Address address) {
		try {
			program.getListing().createData(address, new PointerDataType());
			Data data = program.getListing().getDefinedDataAt(address);
			return data;
		}
		catch (Exception e) {
		}
		return null;
	}

	/**
	 * Returns the name space inside the given parent name space.
	 * If it does not exist, then create it and return it.
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
	 * Returns the class inside the given parent name space.
	 * If it does not exist, then create it and return it.
	 */
	public static Namespace getClassNamespace(Program program, Namespace parentNamespace,
			String namespaceName) throws DuplicateNameException, InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol = symbolTable.getClassSymbol(namespaceName, parentNamespace);
		if (symbol instanceof ClassSymbol) {
			if (symbol.getName().equals(namespaceName)) {
				return (GhidraClass) symbol.getObject();
			}
		}
		return symbolTable.createClass(parentNamespace, namespaceName, SourceType.IMPORTED);
	}

	/**
	 * Creates a symbol.
	 *
	 * TODO - make symbols primary?
	 */
	public static Symbol createSymbol(Program program, Namespace parentNamespace, String symbolName,
			Address symbolAddress) throws InvalidInputException {
		Symbol symbol = program.getSymbolTable().createLabel(symbolAddress, symbolName,
			parentNamespace, SourceType.IMPORTED);
		symbol.setPrimary();
		return symbol;
	}

	/**
	 * Creates a namespace hierarchy using the list of strings specified in namespacePath.
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

	public final static String formatAsObjectiveC(Function function,
			ObjectiveC_MethodType methodType) {
		return formatAsObjectiveC(function.getSignature(), methodType, false);
	}

	public final static String formatAsObjectiveC(FunctionSignature signature,
			ObjectiveC_MethodType methodType, boolean appendSemicolon)
			throws IllegalStateException {
		int colonCount = StringUtilities.countOccurrences(signature.getName(), ':');

		StringTokenizer tokenizer = new StringTokenizer(signature.getName(), ":");
		StringBuffer buffer = new StringBuffer();
		buffer.append(methodType.getIndicator());
		buffer.append(' ');
		buffer.append('(' + signature.getReturnType().getDisplayName() + ')');
		buffer.append(' ');
		ParameterDefinition[] arguments = signature.getArguments();
		int argumentIndex = 2;//skip ID and SEL

		if (arguments.length - 2 != colonCount - 1 && arguments.length - 2 != colonCount) {
			throw new IllegalStateException("Invalid amount of arguments.");
		}
		List<String> tokenList = new ArrayList<String>();
		while (tokenizer.hasMoreTokens()) {
			tokenList.add(tokenizer.nextToken());
		}
		while (tokenList.size() < colonCount) {
			tokenList.add("");
		}
		for (String token : tokenList) {
			buffer.append(token);
			if (argumentIndex < arguments.length) {
				buffer.append(':');
				buffer.append('(' + arguments[argumentIndex].getDataType().getDisplayName() + ')');
				buffer.append("arg" + argumentIndex);
				++argumentIndex;
				if (argumentIndex < arguments.length) {
					buffer.append(' ');
				}
			}
		}
		if (appendSemicolon) {
			buffer.append(';');
		}
		return buffer.toString();
	}

	public final static void createMethods(ObjectiveC1_State state) {
		state.monitor.setMessage("Creating Objective-C Methods...");
		state.monitor.initialize(state.methodMap.size());
		int progress = 0;

		Set<Address> addresses = state.methodMap.keySet();
		for (Address address : addresses) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(++progress);

			ObjectiveC1_Utilities.setThumbBit(state, address);

			BackgroundCommand command = null;

			command = new DisassembleCommand(address, null, true);
			command.applyTo(state.program, state.monitor);

			command = new CreateFunctionCmd(address);
			command.applyTo(state.program, state.monitor);

			//command = new FunctionStackAnalysisCmd(address, false);
			//command.applyTo(state.program, state.monitor);

			ObjectiveC_Method method = state.methodMap.get(address);

			try {
				state.encodings.processMethodSignature(state.program, address, method.getTypes(),
					method.getMethodType());
			}
			catch (Exception e) {
				Msg.error(ObjectiveC1_Utilities.class,
					"Unhandled method signature: " + e.getMessage(), e);
			}
		}
	}

	public final static void createInstanceVariablesC2_OBJC2(ObjectiveC2_State state) {
		state.monitor.setMessage("Creating Objective-C 2.0 Instance Variables...");
		state.monitor.initialize(state.variableMap.size());
		int progress = 0;

		Set<Address> addresses = state.variableMap.keySet();
		for (Address address : addresses) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(++progress);

			ObjectiveC2_InstanceVariable variable = state.variableMap.get(address);
			try {
				state.encodings.processInstanceVariableSignature(state.program, address,
					variable.getType(), variable.getSize());
			}
			catch (Exception e) {
				//System.err.println("Unhandled instance variable signature: "+e.getMessage());//TODO
			}
		}
	}

	/**
	 * This method will remove references to the NULL address
	 * and it will adjust THUMB references to no longer be offcut.
	 */
	public final static void fixupReferences(ObjectiveC1_State state) {
		state.monitor.setMessage("Fixing References...");

		AddressSet addressSet = new AddressSet();

		List<String> sectionNames = state.getObjectiveCSectionNames();
		for (String sectionName : sectionNames) {
			if (state.monitor.isCancelled()) {
				break;
			}
			MemoryBlock block = state.program.getMemory().getBlock(sectionName);
			if (block != null) {//not all blocks will exist
				addressSet.addRange(block.getStart(), block.getEnd());
			}
		}

		state.monitor.initialize(addressSet.getNumAddresses());
		int progress = 0;

		ReferenceManager referenceManager = state.program.getReferenceManager();

		AddressIterator referenceIterator =
			referenceManager.getReferenceSourceIterator(addressSet, true);
		while (referenceIterator.hasNext()) {
			if (state.monitor.isCancelled()) {
				break;
			}
			++progress;
			if ((progress % 100) == 0) {
				state.monitor.setProgress(progress);
			}
			Address sourceAddress = referenceIterator.next();
			Reference[] references = referenceManager.getReferencesFrom(sourceAddress);
			for (Reference reference : references) {
				if (state.monitor.isCancelled()) {
					break;
				}
				if (ObjectiveC1_Utilities.isNull(reference.getToAddress())) {
					referenceManager.delete(reference);
				}
				if (ObjectiveC1_Utilities.isThumb(state.program, reference.getToAddress())) {
					referenceManager.delete(reference);
					referenceManager.addMemoryReference(reference.getFromAddress(),
						reference.getToAddress().subtract(1), reference.getReferenceType(),
						reference.getSource(), reference.getOperandIndex());
				}
			}
		}
	}
}
