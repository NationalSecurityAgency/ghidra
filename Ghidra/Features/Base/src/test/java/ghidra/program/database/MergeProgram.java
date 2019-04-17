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
package ghidra.program.database;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * A special test 'program-like' class that allows clients to *easily* make changes one
 * or more programs.  This is useful for merge tests, which need to setup an environment
 * that is the same for many different programs.
 */
public class MergeProgram {

	private Program[] programs;
	private int[] txIDs;

	public MergeProgram(Program... progs) {

		if (progs == null) {
			throw new IllegalArgumentException("Must pass in valid programs");
		}

		if (progs.length == 0) {
			throw new IllegalArgumentException("Must pass in at least one program");
		}

		programs = progs;
		txIDs = new int[progs.length];
	}

	public Program getProgram() {
		// all programs are changed the same, so any will do
		return programs[0];
	}

	public void removeBookmark(String address, String type) {
		startTransactions();
		try {
			for (Program p : programs) {
				BookmarkManager bm = p.getBookmarkManager();
				Bookmark[] bookmarks = bm.getBookmarks(addr(p, address), type);
				bm.removeBookmark(bookmarks[0]);
			}
		}
		finally {
			endTransations();
		}
	}

	public void setBookmark(String address, String bookmarkType, String category, String comment) {

		startTransactions();
		try {
			for (Program p : programs) {
				BookmarkManager bm = p.getBookmarkManager();
				Address addr = addr(p, address);
				bm.setBookmark(addr, bookmarkType, category, comment);
			}
		}
		finally {
			endTransations();
		}
	}

	public void updateBookmark(String address, String type, String category, String comment) {

		startTransactions();
		try {
			for (Program p : programs) {
				BookmarkManager bm = p.getBookmarkManager();
				Bookmark[] bookmarks = bm.getBookmarks(addr(p, address), type);

				if (category == null) {
					category = bookmarks[0].getCategory();
				}

				if (comment == null) {
					comment = bookmarks[0].getComment();
				}

				bookmarks[0].set(category, comment);
			}
		}
		finally {
			endTransations();
		}
	}

	public void addMemory(String name, String address, int size) {
		startTransactions();
		try {
			for (Program p : programs) {
				Address startAddress = addr(p, address);
				Memory memory = p.getMemory();

				try {
					memory.createInitializedBlock(name, startAddress, size, (byte) 0,
						TaskMonitorAdapter.DUMMY_MONITOR, false);
				}
				catch (Exception e) {
					throw new RuntimeException("Exception building memory", e);
				}
			}
		}
		finally {
			endTransations();
		}
	}

	public Namespace createNamespace(Namespace parent, String name, SourceType type) {
		Namespace result = null;

		startTransactions();
		try {
			for (Program p : programs) {
				SymbolTable symbolTable = p.getSymbolTable();
				try {

					// make sure we get the equivalent namespace for the given program
					Namespace parentNamespace = findMatchingNamespace(p, parent);

					Namespace ns = symbolTable.createNameSpace(parentNamespace, name, type);
					if (result == null) {
						result = ns; // always use the first program for consistency
					}
				}
				catch (Exception e) {
					throw new RuntimeException("Exception creating namespace", e);
				}
			}

			return result;
		}
		finally {
			endTransations();
		}
	}

	public Namespace createClass(Namespace parent, String name, SourceType type) {
		Namespace result = null;

		startTransactions();
		try {
			for (Program p : programs) {
				SymbolTable symbolTable = p.getSymbolTable();
				try {

					// make sure we get the equivalent namespace for the given program
					Namespace parentNamespace = findMatchingNamespace(p, parent);

					Namespace ns = symbolTable.createClass(parentNamespace, name, type);
					if (result == null) {
						result = ns; // always use the first program for consistency
					}
				}
				catch (Exception e) {
					throw new RuntimeException("Exception creating namespace", e);
				}
			}

			return result;
		}
		finally {
			endTransations();
		}
	}

	public Library createExternalLibrary(String name, SourceType type) {
		Library result = null;

		startTransactions();
		try {
			for (Program p : programs) {
				SymbolTable symbolTable = p.getSymbolTable();
				try {
					Library lib = symbolTable.createExternalLibrary(name, type);
					if (result == null) {
						result = lib; // always use the first program for consistency
					}
				}
				catch (Exception e) {
					throw new RuntimeException("Exception creating external lib", e);
				}
			}

			return result;
		}
		finally {
			endTransations();
		}
	}

	public void addExternalLibraryName(String name, SourceType type) {
		startTransactions();
		try {
			for (Program p : programs) {
				ExternalManager externalManager = p.getExternalManager();
				try {
					externalManager.addExternalLibraryName(name, type);
				}
				catch (Exception e) {
					throw new RuntimeException("Exception adding extenal lib name", e);
				}
			}
		}
		finally {
			endTransations();
		}
	}

	public void addExternalLocation(String namespace, String label, String address,
			SourceType type) {
		startTransactions();
		try {
			for (Program p : programs) {
				ExternalManager externalManager = p.getExternalManager();
				Address addr = null;
				if (address != null) {
					addr = addr(p, address);
				}
				try {
					externalManager.addExtLocation(namespace, label, addr, type);
				}
				catch (Exception e) {
					throw new RuntimeException("Exception adding extenal location", e);
				}
			}
		}
		finally {
			endTransations();
		}
	}

	public void addExternalLocation(Namespace namespace, String label, String address,
			SourceType type) {

		startTransactions();
		try {
			for (Program p : programs) {

				// make sure we get the equivalent namespace for the given program
				Namespace parentNamespace = findMatchingNamespace(p, namespace);

				ExternalManager externalManager = p.getExternalManager();
				Address addr = null;
				if (address != null) {
					addr = addr(p, address);
				}
				try {
					externalManager.addExtLocation(parentNamespace, label, addr, type);
				}
				catch (Exception e) {
					throw new RuntimeException("Exception adding extenal location", e);
				}
			}
		}
		finally {
			endTransations();
		}
	}

	public void addExternalLocation(Namespace namespace, String label, String address, DataType dt,
			SourceType type) {

		startTransactions();
		try {
			for (Program p : programs) {

				// make sure we get the equivalent namespace for the given program
				Namespace parentNamespace = findMatchingNamespace(p, namespace);

				ExternalManager externalManager = p.getExternalManager();
				Address addr = null;
				if (address != null) {
					addr = addr(p, address);
				}
				try {
					ExternalLocation loc =
						externalManager.addExtLocation(parentNamespace, label, addr, type);
					loc.setDataType(dt);
				}
				catch (Exception e) {
					throw new RuntimeException("Exception adding extenal location", e);
				}
			}
		}
		finally {
			endTransations();
		}
	}

	public ExternalLocation addExternalFunction(Namespace namespace, String name, String address,
			SourceType type) {

		ExternalLocation result = null;

		startTransactions();
		try {
			for (Program p : programs) {

				// make sure we get the equivalent namespace for the given program
				Namespace parentNamespace = findMatchingNamespace(p, namespace);

				ExternalManager externalManager = p.getExternalManager();
				Address addr = null;
				if (address != null) {
					addr = addr(p, address);
				}
				try {
					ExternalLocation loc =
						externalManager.addExtFunction(parentNamespace, name, addr, type);
					if (result == null) {
						result = loc;
					}
				}
				catch (Exception e) {
					throw new RuntimeException("Exception adding extenal function", e);
				}
			}

			return result;
		}
		finally {
			endTransations();
		}
	}

	public void addExternalFunction(String libname, String name, String address, SourceType type) {
		startTransactions();
		try {
			for (Program p : programs) {

				ExternalManager externalManager = p.getExternalManager();
				Address addr = null;
				if (address != null) {
					addr = addr(p, address);
				}
				try {
					externalManager.addExtFunction(libname, name, addr, type);
				}
				catch (Exception e) {
					throw new RuntimeException("Exception adding extenal function", e);
				}
			}
		}
		finally {
			endTransations();
		}
	}

	public void updateFunction(Function f, boolean customStorage, DataType returnType,
			Parameter... params) {
		startTransactions();
		try {
			for (Program p : programs) {

				Function function = findMatchingFunction(p, f);

				function.setCustomVariableStorage(customStorage);

				try {
					if (returnType != null) {
						function.setReturnType(returnType, SourceType.ANALYSIS);

					}

					for (Parameter param : params) {
						function.addParameter(param, SourceType.USER_DEFINED);
					}

				}
				catch (Exception e) {
					throw new RuntimeException("Exception updating function function", e);
				}
			}
		}
		finally {
			endTransations();
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private Function findMatchingFunction(Program p, Function f) {
		FunctionManager functionManager = p.getFunctionManager();
		return functionManager.getFunctionAt(f.getEntryPoint());
	}

	private Namespace findMatchingNamespace(Program program, Namespace otherNamespace) {
		if (otherNamespace == null) {
			return program.getGlobalNamespace();
		}

		Program source = otherNamespace.getSymbol().getProgram();
		if (source == program) {
			return otherNamespace;
		}
		return getCorrespondingNamespace(source, otherNamespace, program);
	}

	private Namespace getCorrespondingNamespace(Program source, Namespace ns,
			Program otherProgram) {
		if (ns == source.getGlobalNamespace()) {
			return otherProgram.getGlobalNamespace();
		}

		Namespace parent = ns.getParentNamespace();
		Namespace otherNamespace = getCorrespondingNamespace(source, parent, otherProgram);
		SymbolTable symbolTable = otherProgram.getSymbolTable();
		return symbolTable.getNamespace(ns.getName(), otherNamespace);
	}

	private void startTransactions() {
		for (int i = 0; i < programs.length; i++) {
			txIDs[i] = programs[i].startTransaction("TX");
		}
	}

	private void endTransations() {
		for (int i = 0; i < programs.length; i++) {
			programs[i].endTransaction(txIDs[i], true);
		}
	}

	private Address addr(Program pgm, String address) {
		return pgm.getAddressFactory().getAddress(address);
	}

}
