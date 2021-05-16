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
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.listing.Parameter;

/**
 * Interface for requesting specific information about the compiler used to
 * build a Program being analyzed.  Major elements that can be queried include:
 *   - AddressSpaces from the Language plus compiler specific ones like "stack"
 *   - DataOrganization describing size and alignment of primitive data-types: int, long, pointers, etc.
 *   - PrototypeModels describing calling conventions used by the compiler: __stdcall, __thiscall, etc.
 *   - InjectPayloads or p-code that can used for
 *      - Call-fixups, substituting p-code for compiler bookkeeping functions during analysis.
 *      - Callother-fixups, substituting p-code for user-defined p-code operations.
 *   - Memory ranges that the compiler treats as global
 *   - Context and register values known to the compiler over specific memory ranges
 */
public interface CompilerSpec {

	public final static String CALLING_CONVENTION_cdecl = "__cdecl";
	public final static String CALLING_CONVENTION_pascal = "__pascal";
	public final static String CALLING_CONVENTION_thiscall = "__thiscall";
	public final static String CALLING_CONVENTION_stdcall = "__stdcall";
	public final static String CALLING_CONVENTION_fastcall = "__fastcall";
	public final static String CALLING_CONVENTION_vectorcall = "__vectorcall";

	/**
	 * Labels for PrototypeModels that are used by default for various analysis/evaluation
	 * use-cases, when the true model isn't known.  The CompilerSpec maintains a specific
	 * default PrototypeModel to be used for each use-case label.
	 */
	public enum EvaluationModelType {
		EVAL_CURRENT,			// A PrototypeModel used to evaluate the "current" function
		EVAL_CALLED				// A PrototypeModel used to evaluate a "called" function
	}

	/**
	 * Get the Language this compiler spec is based on.  Note that
	 * compiler specs may be reused across multiple languages in the
	 * cspec files on disk, but once loaded in memory are actually
	 * separate objects.  (M:N on disk, 1:N in memory) 
	 * @return the language this compiler spec is based on
	 */
	public Language getLanguage();

	/**
	 * @return a brief description of the compiler spec
	 */
	public CompilerSpecDescription getCompilerSpecDescription();

	/**
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
	 * @param spaceName is the name of the address space
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
	 * @return true if the stack grows with negative offsets
	 */
	public boolean stackGrowsNegative();

	/**
	 * Apply context settings to the ProgramContext
	 * as specified by the configuration
	 * @param ctx is the ProgramContext
	 */
	public void applyContextSettings(DefaultProgramContext ctx);

	/**
	 * @return an array of the prototype models. Each prototype model specifies a calling convention.
	 */
	public PrototypeModel[] getCallingConventions();

	/**
	 * Returns the Calling Convention Model with the given name.
	 * @param name the name of the calling convention to retrieve
	 * @return the calling convention with the given name or null if there is none with that name.
	 */
	public PrototypeModel getCallingConvention(String name);

	/**
	 * @return all possible PrototypeModels, including calling conventions and merge models
	 */
	public PrototypeModel[] getAllModels();

	/**
	 * Returns the prototype model that is the default calling convention or else null.
	 * @return the default calling convention or null.
	 */
	public PrototypeModel getDefaultCallingConvention();

	/**
	 * Get the language that the decompiler produces
	 * @return an enum specifying the language
	 */
	public DecompilerLanguage getDecompilerOutputLanguage();

	/**
	 * Get the evaluation model matching the given type.
	 * If analysis needs to apply a PrototypeModel to a function but a specific model
	 * is not known, then this method can be used to select a putative PrototypeModel
	 * based on the analysis use-case:
	 *    - EVAL_CURRENT indicates the model to use for the "current function" being analyzed
	 *    - EVAL_CALLED indicates the model to use for a function called by the current function
	 * @param modelType is the type of evaluation model
	 * @return prototype evaluation model
	 */
	public PrototypeModel getPrototypeEvaluationModel(EvaluationModelType modelType);

	/**
	 * @param addr is the (start of the) storage location
	 * @return true if the specified storage location has been designated "global" in scope
	 */
	public boolean isGlobal(Address addr);

	public DataOrganization getDataOrganization();

	public PcodeInjectLibrary getPcodeInjectLibrary();

	/**
	 * Get the PrototypeModel corresponding to the given generic calling convention
	 * @param genericCallingConvention is the given generic calling convention
	 * @return the matching model or the defaultModel if nothing matches
	 */
	public PrototypeModel matchConvention(GenericCallingConvention genericCallingConvention);

	/**
	 * Find the best guess at a calling convention model from this compiler spec
	 * given an ordered list of (potential) parameters.
	 * @param params is the ordered list of parameters
	 * @return prototype model corresponding to the specified function signature
	 */
	public PrototypeModel findBestCallingConvention(Parameter[] params);

	/**
	 * Returns whether this language has a property defined.
	 * @param key the property key
	 * @return if the property is defined
	 */
	public boolean hasProperty(String key);

	/**
	 * Return true if function prototypes respect the C-language data-type conversion conventions.
	 * This amounts to converting array data-types to pointer-to-element data-types.
	 * In C, arrays are passed by reference (structures are still passed by value)
	 * @return if the prototype does C-language data-type conversions
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
