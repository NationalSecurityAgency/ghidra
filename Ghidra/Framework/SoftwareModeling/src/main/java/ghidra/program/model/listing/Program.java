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
package ghidra.program.model.listing;

import java.util.Date;

import ghidra.framework.store.LockException;
import ghidra.program.database.IntRangeMap;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * This interface represents the main entry point into an object which
 * stores all information relating to a single program.  This program
 * model divides a program into four major parts: the memory, the symbol table,
 * the equate table, and the listing.  Each of these parts has an extensive
 * interface and can be retrieved via this program interface.  Although the
 * components are divided into separate objects, they are not independent.  Any
 * changes to one component may and probably will affect the other components.
 * Also, the state of one component will restrict the actions of another
 * component.
 * For example, the createCodeUnit() method of listing will fail if memory is
 * undefined at the address where the codeUnit is to be created.
 */
public interface Program extends DataTypeManagerDomainObject {

	public static final String ANALYSIS_PROPERTIES = "Analyzers";
	public static final String DISASSEMBLER_PROPERTIES = "Disassembler";

	/** Name of program information property list */
	public static final String PROGRAM_INFO = "Program Information";
	/** Name of program settings property list */
	public static final String PROGRAM_SETTINGS = "Program Settings";
	/** Name of boolean analyzed property */
	public static final String ANALYZED = "Analyzed";
	/** Name of date created property */
	public static final String DATE_CREATED = "Date Created";
	/** Name of ghidra version property */
	public static final String CREATED_WITH_GHIDRA_VERSION = "Created With Ghidra Version";
	/** Creation date to ask for analysis */
	public static final String ANALYSIS_START_DATE = "2007-Jan-01";
	/** Format string of analysis date */
	public static final String ANALYSIS_START_DATE_FORMAT = "yyyy-MMM-dd";
	/** A date from January 1, 1970 */
	public static final Date JANUARY_1_1970 = new Date(0);

	/** The maximum number of operands for any assembly language */
	public final static int MAX_OPERANDS = 16;

	/**
	 * Get the listing object.
	 * @return the Listing interface to the listing object.
	 */
	public Listing getListing();

	/**
	 * Get the internal program address map
	 * @return internal address map
	 */
	// FIXME!! Should not expose on interface - anything using this should use ProgramDB or avoid using map!
	public AddressMap getAddressMap();

	/**
	 * Returns the program's datatype manager.
	 */
	@Override
	public ProgramBasedDataTypeManager getDataTypeManager();

	/**
	 * Returns the programs function manager.
	 * @return the function manager
	 */
	public FunctionManager getFunctionManager();

	/**
	 * Returns the user-specific data manager for
	 * this program.
	 * @return the program-specific user data manager
	 */
	public ProgramUserData getProgramUserData();

	/**
	 * Get the symbol table object.
	 * @return the symbol table object.
	 */
	public SymbolTable getSymbolTable();

	/**
	
	 * Returns the external manager.
	 * @return the external manager
	 */
	public ExternalManager getExternalManager();

	/**
	 * Get the equate table object.
	 * @return the equate table.
	 */
	public EquateTable getEquateTable();

	/**
	 * Get the memory object.
	 * @return the memory object.
	 */
	public Memory getMemory();

	/**
	 * Get the reference manager.
	 * @return the reference manager
	 */
	public ReferenceManager getReferenceManager();

	/**
	 * Get the bookmark manager.
	 * @return the bookmark manager
	 */
	public BookmarkManager getBookmarkManager();

	/**
	 * Gets the default pointer size in bytes as it may be stored within the program listing.
	 * @return default pointer size.
	 * @see DataOrganization#getPointerSize()
	 */
	public int getDefaultPointerSize();

	/**
	 * Gets the name of the compiler believed to have been used to create this program.
	 * If the compiler hasn't been determined then "unknown" is returned.
	 *
	 * @return name of the compiler or "unknown".
	 */
	public String getCompiler();

	/**
	 * Sets the name of the compiler which created this program.
	 * @param compiler   the name
	 */
	public void setCompiler(String compiler);

	/**
	 * Gets the path to the program's executable file.
	 * For example, <code>C:\Temp\test.exe</code>.
	 * This will allow plugins to execute the program.
	 *
	 * @return String  path to program's exe file
	 */
	public String getExecutablePath();

	/**
	 * Sets the path to the program's executable file.
	 * For example, <code>C:\Temp\test.exe</code>.
	 *
	 * @param path  the path to the program's exe
	 */
	public void setExecutablePath(String path);

	/**
	 * Returns a value corresponding to the original file format.
	 * @return original file format used to load program or null if unknown
	 */
	public String getExecutableFormat();

	/**
	 * Sets the value corresponding to the original file format.
	 * @param format the binary file format string to set.
	 */
	public void setExecutableFormat(String format);

	/**
	 * Returns a value corresponding to the original binary file MD5 hash.
	 * @return original loaded file MD5 or null
	 */
	public String getExecutableMD5();

	/**
	 * Sets the value corresponding to the original binary file MD5 hash.
	 * @param md5 MD5 binary file hash
	 */
	public void setExecutableMD5(String md5);

	/**
	 * Sets the value corresponding to the original binary file SHA256 hash.
	 * @param sha256 SHA256 binary file hash
	 */
	public void setExecutableSHA256(String sha256);

	/**
	 * Returns a value corresponding to the original binary file SHA256 hash.
	 * @return original loaded file SHA256 or null
	 */
	public String getExecutableSHA256();

	/**
	 * Returns the creation date of this program.
	 * If the program was created before this property
	 * existed, then Jan 1, 1970 is returned.
	 * @return the creation date of this program
	 */
	public Date getCreationDate();

	/**
	 * Gets the relocation table.
	 * @return relocation table object
	 */
	public RelocationTable getRelocationTable();

	/**
	 * Returns the language used by this program.
	 * @return the language used by this program.
	 */
	public Language getLanguage();

	/** 
	 * Returns the CompilerSpec currently used by this program.
	 * @return the compilerSpec currently used by this program.
	 */
	public CompilerSpec getCompilerSpec();

	/**
	 * Return the name of the language used by this program.
	 * 
	 * @return the name of the language
	 */
	public LanguageID getLanguageID();

	/**
	 * Get the user propertyMangager stored with this program. The user property
	 * manager is used to store arbitrary address indexed information associated
	 * with the program.
	 *
	 * @return the user property manager.
	 */
	public PropertyMapManager getUsrPropertyManager();

	/**
	 * Returns the program context.
	 * @return the program context object
	 */
	public ProgramContext getProgramContext();

	/**
	 * get the program's minimum address.
	 * @return the program's minimum address or null if no memory blocks
	 * have been defined in the program.
	 */
	public Address getMinAddress();

	/**
	 * Get the programs maximum address.
	 * @return the program's maximum address or null if no memory blocks
	 * have been defined in the program.
	 */
	public Address getMaxAddress();

	/**
	 * Get the program changes since the last save as a set of addresses.
	 * @return set of changed addresses within program.
	 */
	public ProgramChangeSet getChanges();

	/**
	 *  Returns the AddressFactory for this program.
	 *  @return the program address factory
	 */
	public AddressFactory getAddressFactory();

	/**
	 * Return an array of Addresses that could represent the given
	 * string.
	 * @param addrStr the string to parse.
	 * @return zero length array if addrStr is properly formatted but
	 * no matching addresses were found or if the address is improperly formatted.
	 */
	public Address[] parseAddress(String addrStr);

	/**
	 * Return an array of Addresses that could represent the given
	 * string.
	 * @param addrStr the string to parse.
	 * @param caseSensitive whether or not to process any addressSpace names as case sensitive.
	 * @return zero length array if addrStr is properly formatted but
	 * no matching addresses were found or if the address is improperly formatted.
	 */
	public Address[] parseAddress(String addrStr, boolean caseSensitive);

	/**
	 * Invalidates any caching in a program.
	 * NOTE: Over-using this method can adversely affect system performance.
	 */
	public void invalidate();

	/**
	 * Returns the register with the given name;
	 * @param name the name of the register to retrieve
	 * @return register or null
	 */
	public Register getRegister(String name);

	/**
	 * Returns the largest register located at the specified address
	 * 
	 * @param addr register minimum address
	 * @return largest register at addr or null
	 */
	public Register getRegister(Address addr);

	/**
	 * Returns all registers located at the specified address
	 * 
	 * @param addr register minimum address
	 * @return all registers at addr
	 */
	public Register[] getRegisters(Address addr);

	/**
	 * Returns a specific register based upon its address and size
	 * @param addr register address
	 * @param size the size of the register (in bytes);
	 * @return register or null 
	 */
	public Register getRegister(Address addr, int size);

	/**
	 * Returns the register which corresponds to the specified varnode
	 * @param varnode the varnode
	 * @return register or null
	 */
	public Register getRegister(Varnode varnode);

	/**
	 * Returns the current program image base address
	 * @return program image base address within default space
	 */
	public Address getImageBase();

	/**
	 * Sets the program's image base address.
	 * @param base the new image base address;
	 * @param commit if false, then the image base change is temporary and does not really change
	 * the program and will be lost once the program is closed.  If true, the change is permanent
	 * and marks the program as "changed" (needs saving).
	 * @throws AddressOverflowException if the new image would cause a memory block to end past the
	 * the address space.
	 * @throws LockException if the program is shared and the user does not have an exclusive checkout.
	 * This will never be thrown if commit is false.
	 * @throws IllegalStateException if the program state is not suitable for setting the image base.
	 */
	public void setImageBase(Address base, boolean commit)
			throws AddressOverflowException, LockException, IllegalStateException;

	/**
	 * Restores the last committed image base.
	 */
	public void restoreImageBase();

	/**
	 * Sets the language for the program. If the new language is "compatible" with the old language,
	 * the addressMap is adjusted then the program is "re-disassembled".
	 * @param language the new language to use.
	 * @param compilerSpecID the new compiler specification ID
	 * @param forceRedisassembly if true a redisassembly will be forced.  This should always be false.
	 * @param monitor the task monitor
	 * @throws IllegalStateException thrown if any error occurs, including a cancelled monitor, which leaves this 
	 * program object in an unusable state.  The current transaction should be aborted and the program instance
	 * discarded.
	 * @throws IncompatibleLanguageException thrown if the new language is too different from the
	 * existing language.
	 * @throws LockException if the program is shared and not checked out exclusively.
	 */
	public void setLanguage(Language language, CompilerSpecID compilerSpecID,
			boolean forceRedisassembly, TaskMonitor monitor)
			throws IllegalStateException, IncompatibleLanguageException, LockException;

	/**
	 * Returns the global namespace for this program
	 * @return the global namespace
	 */
	public Namespace getGlobalNamespace();

	/**
	 * Create a new AddressSetPropertyMap with the specified name. 
	 * @param name name of the property map.
	 * @return the newly created property map.
	 * @throws DuplicateNameException if a property map already exists with the given name.
	 */
	public AddressSetPropertyMap createAddressSetPropertyMap(String name)
			throws DuplicateNameException;

	/**
	 * Create a new IntRangeMap with the specified name.
	 * 
	 * @param name name of the property map.
	 * @return the newly created property map.
	 * @throws DuplicateNameException if a property map already exists with the given name.
	 */
	public IntRangeMap createIntRangeMap(String name) throws DuplicateNameException;

	/**
	 * Get the property map with the given name.
	 * @param name name of the property map
	 * @return null if no property map exist with the given name
	 */
	public AddressSetPropertyMap getAddressSetPropertyMap(String name);

	/**
	 * Get the property map with the given name.
	 * @param name name of the property map
	 * @return null if no property map exist with the given name
	 */
	public IntRangeMap getIntRangeMap(String name);

	/**
	 * Remove the property map from the program.
	 * @param name name of the property map to remove
	 */
	public void deleteAddressSetPropertyMap(String name);

	/**
	 * Remove the property map from the program.
	 * @param name name of the property map to remove
	 */
	public void deleteIntRangeMap(String name);

	/**
	 * Returns an ID that is unique for this program.  This provides an easy way to store
	 * references to a program across client persistence.
	 * @return unique program ID
	 */
	public long getUniqueProgramID();
}
