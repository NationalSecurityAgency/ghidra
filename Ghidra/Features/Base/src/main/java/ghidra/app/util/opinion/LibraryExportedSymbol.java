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

/**
 * A class to represent an exported symbol in a library (or DLL).
 * 
 */
class LibraryExportedSymbol {

	private String libName;
	private int memsize;
	private int ordinal = -1;
	private String symbolName;
	private String fowardLibraryName;
	private String fowardSymbolName;
	private int purge;
	private boolean noReturn;
	private String comment;

	LibraryExportedSymbol(String libName, int memsize, int ordinal, String symbolName,
			String fowardLibraryName, String fowardSymbolName, int purge, boolean noReturn,
			String comment) {
		this.libName = libName;
		this.memsize = memsize;
		this.ordinal = ordinal;
		this.symbolName = symbolName;
		this.purge = purge;
		this.noReturn = noReturn;
		this.comment = comment;
		this.fowardLibraryName = fowardLibraryName;
		this.fowardSymbolName = fowardSymbolName;
	}

	/**
	 * Returns the name of the library containing this
	 * exported symbol. For example "user32.dll" or "libc.so".
	 * @return the library name
	 */
	String getLibraryName() {
		return libName;
	}

	/**
	 * Returns the ordinal value of this symbol.
	 * A value of -1 indicates that this symbol
	 * is only exported by name.
	 * @return the ordinal value of this symbol
	 */
	int getOrdinal() {
		return ordinal;
	}

	/**
	 * Returns the name of this symbol.
	 * This value could be null since some libraries
	 * only export by ordinal value.
	 * @return the name of this symbol
	 */
	String getName() {
		return symbolName;
	}

	/**
	 * Returns the purge value of the function related
	 * to this exported symbol. The purge value
	 * is the number of bytes purged from the stack
	 * when the function returns.
	 * 
	 * -2 purge value is used to prevent infinite loops in recursion.
	 * 
	 * @return the purge value of the function or -1 (if unable to resolve the purge value)
	 */
	int getPurge() {
		if (isFowardEntry() && purge == -1) {
			processForwardedEntry();
		}

		if (purge == -2) {
			purge = -1;
		}

		return purge;
	}

	/**
	 * Returns the No-Return value of the function related
	 * to this exported symbol.
	 * 
	 * -2 purge value is used to prevent infinite loops in recursion.
	 * 
	 * @return the No-Return value of the function
	 */
	boolean hasNoReturn() {
		if (isFowardEntry() && purge == -1) {
			processForwardedEntry();
		}

		if (purge == -2) {
			purge = -1;
		}

		return noReturn;
	}

	/**
	 * Attempt to get purge value and noReturn from forwarded entry.
	 * If purge value is not -1, these values have already been retrieved.
	 * 
	 * -2 purge value is used to prevent infinite loops in recursion.
	 */
	private synchronized void processForwardedEntry() {

		purge = -2;
		LibrarySymbolTable lib = LibraryLookupTable.getSymbolTable(fowardLibraryName, memsize);
		if (lib == null) {
			return;
		}

		LibraryExportedSymbol libSym = lib.getSymbol(fowardSymbolName);
		if (libSym == null) {
			return;
		}

		purge = libSym.getPurge();

		if (purge != -1) {
			noReturn = libSym.hasNoReturn();
		}
	}

	/**
	 * Returns the comment from the symbol file.
	 * @return the comment from the symbol file
	 */
	String getComment() {
		return comment;
	}

	/**
	 * @return true if this symbol is fowarded to another library
	 */
	boolean isFowardEntry() {
		return fowardLibraryName != null;
	}

	/**
	 * @return the fowarded library name
	 */
	String getFowardLibraryName() {
		return fowardLibraryName;
	}

	/**
	 * @return the fowarded symbol name
	 */
	String getFowardSymbolName() {
		return fowardSymbolName;
	}

	void setName(String name) {
		symbolName = name;
	}

	// TODO: Add toString() method
}
