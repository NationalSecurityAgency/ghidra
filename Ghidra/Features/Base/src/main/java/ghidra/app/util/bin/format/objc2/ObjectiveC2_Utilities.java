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
package ghidra.app.util.bin.format.objc2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.database.symbol.ClassSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Conv;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

final class ObjectiveC2_Utilities {

	/**
	 * Reads the next index value. If is32bit is true, then 4 bytes
	 * will be read to form index. Otherwise, 8 bytes will be read to form index.
	 */
	static long readNextIndex(BinaryReader reader, boolean is32bit) throws IOException {
		if (is32bit) {
			return reader.readNextInt() & Conv.INT_MASK;
		}
		return reader.readNextLong();
	}

	/**
	 * Returns the name space inside the given parent name space.
	 * If it does not exist, then create it and return it.
	 */
	static Namespace getNamespace(Program program, Namespace parentNamespace, String namespaceName)
			throws DuplicateNameException, InvalidInputException {
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
	static Namespace getClassNamespace(Program program, Namespace parentNamespace,
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
	 * Creates a symbol with the given name at the specified address.
	 * The symbol will be created in a name space with the name of
	 * the memory block that contains the address.
	 */
	public static Symbol createSymbolUsingMemoryBlockAsNamespace(Program program, Address address,
			String name, SourceType sourceType)
			throws DuplicateNameException, InvalidInputException {

		SymbolTable symbolTable = program.getSymbolTable();
		Memory memory = program.getMemory();

		MemoryBlock block = memory.getBlock(address);
		String namespaceName = block.getName();

		Namespace namespace = symbolTable.getNamespace(namespaceName, program.getGlobalNamespace());
		if (namespace == null) {
			namespace = symbolTable.createNameSpace(program.getGlobalNamespace(), namespaceName,
				sourceType);
		}

		return symbolTable.createLabel(address, name, namespace, SourceType.ANALYSIS);
	}

}
