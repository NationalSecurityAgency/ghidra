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
package ghidra.program.model.pcode;

import java.util.ArrayList;

import generic.hash.SimpleCRC32;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.symbol.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class DataTypeSymbol {
	private Symbol sym;			// Traditional symbol object
	private DataType datatype;		// Datatype associated with the symbol
	private String nmroot;			// root of the name
	private String category;		// datatype category

	public DataTypeSymbol(DataType dt, String nr, String cat) {
		sym = null;
		datatype = dt;
		nmroot = nr;
		category = cat;
	}

	public Symbol getSymbol() {
		return sym;
	}

	public Address getAddress() {
		return sym.getAddress();
	}

	public DataType getDataType() {
		return datatype;
	}

	private String buildHashedDataType(DataTypeManager dtmanage) {
		if (datatype instanceof FunctionSignature) {
			if (dtmanage.contains(datatype))
				return null;					// Signature is already in the manager, shouldn't change name
		}
		else {
			if (!dtmanage.contains(datatype))
				return null;					// Do not make typedef unless datatype is in our manager
			datatype = new TypedefDataType("mytypedef", datatype);
		}
		// Create the name and the category
		CategoryPath path = new CategoryPath(category);
		String hash = generateHash(datatype);
		String type_hashname = "dt_" + hash;
		try {
			datatype.setNameAndCategory(path, type_hashname);
		}
		catch (InvalidNameException e) {
			return null;
		}
		catch (DuplicateNameException e) {
			return null;
		}
		DataType preexists = dtmanage.getDataType(path, type_hashname);
		if (preexists != null) {		// Named datatype already exists
			if (preexists.isEquivalent(datatype)) {		// If this is the right type
				datatype = preexists;
				return hash;							// We are done
			}
			return null;								// Otherwise we can't proceed
		}
		datatype = dtmanage.addDataType(datatype, DataTypeConflictHandler.KEEP_HANDLER);
		return hash;
	}

	private String buildSymbolName(String hash, Address addr) {
		return nmroot + '_' + Long.toHexString(addr.getOffset()) + '_' + hash;
	}

	public void writeSymbol(SymbolTable symtab, Address addr, Namespace namespace,
			DataTypeManager dtmanage, boolean clearold) throws InvalidInputException {
		if (clearold)
			deleteSymbols(nmroot, addr, symtab, namespace);
		String hash = buildHashedDataType(dtmanage);
		if (hash == null)
			throw new InvalidInputException("Unable to create datatype associated with symbol");
		String symname = buildSymbolName(hash, addr);
		HighFunction.createLabelSymbol(symtab, addr, symname, namespace, SourceType.USER_DEFINED,
			false);
	}

	public static void deleteSymbols(String nmroot, Address addr, SymbolTable symtab,
			Namespace space) throws InvalidInputException {
		ArrayList<Symbol> dellist = new ArrayList<Symbol>();
		SymbolIterator iter = symtab.getSymbols(space);
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			if (!sym.getName().startsWith(nmroot))
				continue;
			if (sym.getSymbolType() != SymbolType.LABEL)
				continue;
			if (!addr.equals(sym.getAddress()))
				continue;
			if (sym.hasReferences())
				throw new InvalidInputException("DataTypeSymbol has a reference");
			dellist.add(sym);
		}
		for (Symbol s : dellist) {
			s.delete();
		}
	}

	public static DataTypeSymbol readSymbol(String cat, Symbol s) {
		if (s.getSymbolType() != SymbolType.LABEL) {
			throw new IllegalArgumentException("Expected CODE symbol");
		}
		String hash = extractHash(s.getName());
		String nmr = extractNameRoot(s.getName());
		if (hash == null)
			return null;
		DataTypeManager dtmanage = s.getProgram().getDataTypeManager();
		DataType dt = dtmanage.getDataType(new CategoryPath(cat), "dt_" + hash);
		if (dt == null)
			return null;
		if (dt instanceof TypeDef)
			dt = ((TypeDef) dt).getBaseDataType();
		if (!(dt instanceof FunctionSignature)) {
			return null;
		}

		DataTypeSymbol res = new DataTypeSymbol(dt, nmr, cat);
		res.sym = s;
		return res;
	}

	public static String generateHash(DataType dt) {
		String material;
		if (dt instanceof FunctionSignature)
			material = ((FunctionSignature) dt).getPrototypeString();
		else if (dt instanceof TypeDef) {
			material = ((TypeDef) dt).getDataType().getPathName();
		}
		else {
			material = null;		// No hash scheme
		}

		int hash = 0x12cf91ab;		// Initial hash
		if (material != null) {
			for (int i = 0; i < material.length(); ++i) {
				hash = SimpleCRC32.hashOneByte(hash, material.charAt(i));
			}
		}
		return Integer.toHexString(hash);
	}

	public static String extractHash(String symname) {
		int last = symname.lastIndexOf('_');
		if (last < 0)
			return null;
		return symname.substring(last + 1);
	}

	public static String extractNameRoot(String symname) {
		int first = symname.indexOf('_');
		if (first < 0)
			return "";
		return symname.substring(0, first);
	}

}
