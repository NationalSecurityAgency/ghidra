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

import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.listing.*;

/**
 * Interface for classes that hold compiler option information
 */
public interface CompilerSpec {

	public final static String CALLING_CONVENTION_cdecl = "__cdecl";
	public final static String CALLING_CONVENTION_pascal = "__pascal";
	public final static String CALLING_CONVENTION_thiscall = "__thiscall";
	public final static String CALLING_CONVENTION_stdcall = "__stdcall";
	public final static String CALLING_CONVENTION_fastcall = "__fastcall";
	public final static String CALLING_CONVENTION_vectorcall = "__vectorcall";

	/**
	 * Get the Language this compiler spec is based on.  Note that
	 * compiler specs may be reused across multiple languages in the
	 * cspec files on disk, but once loaded in memory are actually
	 * separate objects.  (M:N on disk, 1:N in memory) 
	 * @return the language this compiler spec is based on
	 */
	public Language getLanguage();

	/**
	 * Returns a brief description of the compiler spec
	 */
	public CompilerSpecDescription getCompilerSpecDescription();

	/**
	 * Returns the id string associated with this compiler spec;
	 * @return the id string associated with this compiler spec;
	 */
	public CompilerSpecID getCompilerSpecID();

	/**
	 * Get the default Stack Pointer register for this language if there is one.
	 * 
	 * @return default stack pointer register.
	 */
	public Register getStackPointer();

	/**
	 * Indicates whether variables are right-justified within the 
	 * stack alignment.
	 * @return true if right stack justification applies.
	 */
	public boolean isStackRightJustified();

	/**
	 * Get an address space by name.  This can be value added over the normal AddressFactory.getAddressSpace
	 * routine because the compiler spec can refer to special internal spaces like the stack space
	 * @param spaceName
	 * @return the corresponding AddressSpace object
	 */
	public AddressSpace getAddressSpace(String spaceName);
	
	/**
	 * Get the stack address space defined by this specification
	 * @return stack address space
	 */
	public AddressSpace getStackSpace();

	/**
	 * Get the physical space used for stack data storage
	 * @return address space which contains the stack
	 */
	public AddressSpace getStackBaseSpace();

	/**
	 * Returns true if stack grows with negative offsets
	 */
	public boolean stackGrowsNegative();

	/**
	 * Apply context settings to the ProgramContext
	 * as specified by the configuration
	 * @param ctx is the ProgramContext
	 */
	public void applyContextSettings(DefaultProgramContext ctx);

	/**
	 * Returns an array of the prototype models. Each prototype model specifies a calling convention.
	 */
	public PrototypeModel[] getCallingConventions();

	/**
	 * Returns the Calling Convention Model with the given name.
	 * @param name the name of the calling convention to retrieve
	 * @return the calling convention with the given name or null if there is none with that name.
	 */
	public PrototypeModel getCallingConvention(String name);

	/**
	 * Returns an array of the named prototype models. Each prototype model specifies a calling convention.
	 */
	public PrototypeModel[] getNamedCallingConventions();

	/**
	 * Returns the prototype model that is the default calling convention or else null.
	 * @return the default calling convention or null.
	 */
	public PrototypeModel getDefaultCallingConvention();

	/**
	 * Returns true if specified address location has been designated global
	 * @param addr address location
	 */
	public boolean isGlobal(Address addr);

	public DataOrganization getDataOrganization();
	
	public PcodeInjectLibrary getPcodeInjectLibrary();

	/**
	 * Register program-specific compiler-spec options
	 * @param program
	 */
	public void registerProgramOptions(Program program);

	/**
	 * Get the program-specific prototype evaluation model.
	 * @param program
	 * @return prototype evaluation model
	 */
	public Object getPrototypeEvaluationModel(Program program);
	
	/**
	 * Get the language that the decompiler produces
	 * @param program
	 * @return an enum specifying the language
	 */
	public DecompilerLanguage getDecompilerOutputLanguage(Program program);

	/**
	 * Get the PrototypeModel based on the genericCallingConvention
	 * @param genericCallingConvention
	 * @return the matching model or the defaultModel if nothing matches
	 */
	public PrototypeModel matchConvention(GenericCallingConvention genericCallingConvention);
	
	/**
	 * Find the best guess at a calling convention model from this compiler spec
	 * given an ordered list of (potential) parameters.
	 * @return prototype model corresponding to the specified function signature
	 */
	public PrototypeModel findBestCallingConvention(Parameter[] params);

	/**
	 * Returns whether this lanugage has a property defined.
	 * @param key the property key
	 * @return if the property is defined
	 */
	public boolean hasProperty(String key);
	
	/**
	 * Return true if function prototypes respect the C-language datatype conversion conventions.
	 * This amounts to converting array datatypes to pointer-to-element datatypes.
	 * In C, arrays are passed by reference (structures are still passed by value)
	 * @return
	 */
	public boolean doesCDataTypeConversions();

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
}
