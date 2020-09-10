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
package ghidra.program.model.lang;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import ghidra.app.plugin.processors.generic.MemoryBlockDefinition;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.util.AddressLabelInfo;
import ghidra.util.ManualEntry;
import ghidra.util.task.TaskMonitor;

public interface Language {

	/**
	 * Returns the LanguageID of this language, which is used as a primary key to
	 * find the language when Ghidra loads it.
	 * @return the LanguageID of this language
	 */
	public LanguageID getLanguageID();

	/**
	 * Returns the LanguageDescription of this language, which contains useful
	 * information about the characteristics of the language.
	 * @return the LanguageDescription of this language
	 */
	public LanguageDescription getLanguageDescription();

	/**
	 * Returns a parallel instruction helper for this language or null
	 * if one has not been defined. 
	 * @return parallel instruction helper or null if not applicable
	 */
	public ParallelInstructionLanguageHelper getParallelInstructionHelper();

	/**
	 * Returns the processor name on which this language is based.
	 * 
	 * For example, 30386, Pentium, 68010, etc.
	 * 
	 * @return the processor name
	 */
	public Processor getProcessor();

	/**
	 * Returns the major version for this language. Returning a version number
	 * different than before could cause the program to try and "update" itself.
	 * Those languages which do not support this feature may always return a
	 * constant value of 1.
	 * 
	 * @return the language version number
	 */
	public int getVersion();

	/**
	 * Returns the minor version for this language. Returning a minor version
	 * number different than before could cause the program to try and "update"
	 * itself. Those languages which do not support this feature may always
	 * return a constant value of 0.
	 * 
	 * @return the language minor version number
	 */
	public int getMinorVersion();

	/**
	 * Get the AddressFactory for this language. The returned Address factory will allow
	 * addresses associated with physical, constant and unique spaces to be instantiated.  
	 * NOTE! this factory does not know about compiler or program specified spaces.  
	 * Spaces such as stack and overlay spaces are not defined by the language - 
	 * if these are needed, Program.getAddressFactory() should be used instead.
	 * 
	 * @return the AddressFactory for this language.
	 * @see Program#getAddressFactory()
	 */
	public AddressFactory getAddressFactory();

	/**
	 * Get the default memory/code space.
	 * @return default address space
	 */
	public AddressSpace getDefaultSpace();

	/**
	 * Get the preferred data space used by loaders for data sections.
	 * @return default data address space
	 */
	public AddressSpace getDefaultDataSpace();

	/**
	 * get the Endian type for this language. (If a language supports both, then
	 * this returns an initial or default value.)
	 * 
	 * @return true for BigEndian, false for LittleEndian.
	 */
	public boolean isBigEndian();

	/**
	 * Get instruction alignment in terms of bytes.
	 * 
	 * @return instruction alignment
	 */
	public int getInstructionAlignment();

	/**
	 * Return true if the instructions in this language support Pcode.
	 * 
	 * @return true if language supports the use of pcode
	 */
	public boolean supportsPcode();

	/**
	 * Returns true if the language has defined the specified location as
	 * volatile.
	 * 
	 * @param addr location address
	 * @return true if specified address is within a volatile range
	 */
	public boolean isVolatile(Address addr);

	/**
	 * Get the InstructionPrototype that matches the bytes presented by the
	 * MemBuffer object.
	 * 
	 * @param buf
	 *            the MemBuffer that presents the bytes in Memory at some
	 *            address as if they were an array of bytes starting at index 0.
	 * @param context
	 *            the processor context at the address to be disassembled
	 * @param inDelaySlot
	 *            true if this instruction should be parsed as if it were in a
	 *            delay slot
	 * 
	 * @return the InstructionPrototype that matches the bytes in buf.
	 * @exception InsufficientBytesException
	 *                thrown if there are not enough bytes in memory to satisfy
	 *                a legal instruction.
	 * @exception UnknownInstructionException
	 *                thrown if the byte pattern does not match any legal
	 *                instruction.
	 */
	public InstructionPrototype parse(MemBuffer buf, ProcessorContext context, boolean inDelaySlot)
			throws InsufficientBytesException, UnknownInstructionException;

	/**
	 * Get the total number of user defined pcode names.
	 * 
	 * Note: only works for Pcode based languages
	 * 
	 * @return number of user defined pcodeops
	 */
	public int getNumberOfUserDefinedOpNames();

	/**
	 * Get the user define name for a given index. Certain pcode has operations
	 * defined only by name that when the pcode returns, only the index is
	 * known.
	 * 
	 * Note: only works for Pcode based languages
	 * 
	 * @param index user defined pcodeop index
	 * @return pcodeop name or null if not defined
	 */
	public String getUserDefinedOpName(int index);

	/**
	 * Returns all the registers (each different size is a different register)
	 * for an address.
	 * 
	 * @param address
	 *            the register address for which to return all registers.
	 * @return all the registers (each different size is a different register)
	 *         for an address.
	 */
	public Register[] getRegisters(Address address);

	/**
	 * Get a register given the address space it is in, its offset in the space
	 * and its size.
	 * 
	 * @param addrspc
	 *            address space the register is in
	 * @param offset
	 *            offset of the register in the space
	 * @param size
	 *            size of the register in bytes
	 * @return the register
	 */
	public Register getRegister(AddressSpace addrspc, long offset, int size);

	/**
	 * Get an unsorted unmodifiable list of Register objects that this language defines
	 * (including context registers).
	 * 
	 * @return unmodifiable list of processor registers.
	 */
	public List<Register> getRegisters();

	/**
	 * Get an alphabetical sorted unmodifiable list of original register names 
	 * (including context registers).  Names correspond to orignal register
	 * name and not aliases which may be defined.
	 * 
	 * @return alphabetical sorted unmodifiable list of original register names.
	 */
	public List<String> getRegisterNames();

	/**
	 * Get a register given the name of the register
	 * 
	 * @param name
	 *            Register name
	 * @return the register
	 */
	public Register getRegister(String name);

	/**
	 * Get a register given it's underlying address location and size.
	 * 
	 * @param addr
	 *            location of the register in its address space
	 * @param size 
	 *            the size of the register (in bytes).  A value of 0 will return the 
	 *            largest register at the specified addr
	 * @return the register
	 */
	public Register getRegister(Address addr, int size);

	/**
	 * Get the default program counter register for this language if there is
	 * one.
	 * 
	 * @return default program counter register.
	 */
	public Register getProgramCounter();

	/**
	 * Returns processor context base register or null if one has not been defined by the
	 * language. 
	 * @return base context register or null if not defined
	 */
	public Register getContextBaseRegister();

	/**
	 * Get an unsorted unmodifiable list of processor context registers that this language defines
	 * (includes context base register and its context field registers).
	 * 
	 * @return unmodifiable list of processor registers.
	 */
	public List<Register> getContextRegisters();

	/**
	 * Returns the default memory blocks for this language.
	 * @return the default memory blocks for this language
	 */
	public MemoryBlockDefinition[] getDefaultMemoryBlocks();

	/**
	 * Returns the default symbols for this language.  This list does not 
	 * contain registers.
	 * @return the default symbols for this language
	 */
	public List<AddressLabelInfo> getDefaultSymbols();

	/**
	 * Returns the name of the segmented space for this language, or the
	 * empty string if the memory model for this language is not
	 * segmented.
	 * @return the name of the segmented space or ""
	 */
	public String getSegmentedSpace();

	/**
	 * Returns an AddressSetView of the volatile addresses for this language
	 * @return an AddressSetView of the volatile addresses for this language
	 */
	public AddressSetView getVolatileAddresses();

	/**
	 * Apply context settings to the ProgramContext as specified by the
	 * configuration
	 * 
	 * @param ctx
	 *            is the default program context
	 */
	public void applyContextSettings(DefaultProgramContext ctx);

	/**
	 * Refreshes the definition of this language if possible.  Use of this method is 
	 * intended for development purpose only since stale references to prior
	 * language resources (e.g., registers) may persist.
	 * @param taskMonitor monitor for progress back to the user
	 * @throws IOException if error occurs while reloading language spec file(s)
	 */
	public void reloadLanguage(TaskMonitor taskMonitor) throws IOException;

	/**
	 * Returns a list of all compatible compiler spec descriptions.
	 * The first item in the list is the default.
	 * @return list of all compatible compiler specifications descriptions
	 */
	public List<CompilerSpecDescription> getCompatibleCompilerSpecDescriptions();

	/**
	 * Returns the compiler spec associated with a given CompilerSpecID.
	 * @param compilerSpecID the compiler spec id
	 * @return the compiler spec associated with the given id
	 * @throws CompilerSpecNotFoundException if no such compiler spec exists
	 */
	public CompilerSpec getCompilerSpecByID(CompilerSpecID compilerSpecID)
			throws CompilerSpecNotFoundException;

	/**
	 * Returns the default compiler spec for this language, which is used
	 * when a loader cannot determine the compiler spec or for upgrades when a
	 * program had no compiler spec registered (seriously old program, like
	 * Ghidra 4.1 or earlier).  NOTE: this has NOTHING to do with the
	 * compiler spec registered for a program.  Use Program.getCompilerSpec()
	 * for that! 
	 * @return the default compiler spec for this language
	 */
	public CompilerSpec getDefaultCompilerSpec();

	/**
	 * Returns whether this lanugage has a property defined.
	 * @param key the property key
	 * @return if the property is defined
	 */
	public boolean hasProperty(String key);

	/**
	 * Gets the value of a property as an int, returning defaultInt if undefined.
	 * @param key the property key
	 * @param defaultInt the default value to return if property is undefined
	 * @return the property value as an int, or the default value if undefined
	 */
	public int getPropertyAsInt(String key, int defaultInt);

	/**
	 * Gets the value of a property as a boolean, returning defaultBoolean if undefined.
	 * @param key the property key
	 * @param defaultBoolean the default value to return if property is undefined
	 * @return the property value as a boolean, or the default value if undefined
	 */
	public boolean getPropertyAsBoolean(String key, boolean defaultBoolean);

	/**
	 * Gets the value of a property as a String, returning defaultString if undefined.
	 * @param key the property key
	 * @param defaultString the default value to return if property is undefined
	 * @return the property value as a String, or the default value if undefined
	 */
	public String getProperty(String key, String defaultString);

	/**
	 * Gets a property defined for this language, or null if that property isn't defined.
	 * @param key the property key
	 * @return the property value, or null if not defined
	 */
	public String getProperty(String key);

	/**
	 * Returns a read-only set view of the property keys defined on this language.
	 * @return read-only set of property keys
	 */
	public Set<String> getPropertyKeys();

	/**
	 * Returns whether the language has a valid manual defined.
	 * @return if the language has a manual
	 */
	public boolean hasManual();

	/**
	 * Get the ManualEntry for the given instruction mnemonic.
	 * 
	 * @param instructionMnemonic
	 *            the instruction mnemonic
	 * @return the ManualEntry or null.  A default manual entry will be returned if 
	 * an instruction can not be found within the index and a manual exists.
	 */
	public ManualEntry getManualEntry(String instructionMnemonic);

	/**
	 * Returns a read-only set view of the instruction mnemonic keys defined on
	 * this language.
	 * 
	 * @return read-only set of instruction mnemonic keys
	 */
	public Set<String> getManualInstructionMnemonicKeys();

	/**
	 * Returns the exception generated trying to load the manual, or null if it succeeded.
	 * @return the exception generated trying to load the manual, or null if it succeeded
	 */
	public Exception getManualException();

	/**
	 * Returns an unmodifiable list of vector registers, sorted first by size and then by name.
	 * @return unmodifiable list of vector registers.
	 */
	public List<Register> getSortedVectorRegisters();

}
