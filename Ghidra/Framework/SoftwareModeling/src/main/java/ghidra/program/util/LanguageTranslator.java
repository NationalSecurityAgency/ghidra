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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * NOTE:  ALL LanguageTranslator CLASSES MUST END IN "LanguageTranslator".  If not,
 * the ClassSearcher will not find them.
 * 
 * <code>LanguageTranslator</code> provides translation capabilities used by Program.setLanguage
 * when converting a program from one language to another or from one version to another.
 * <br>
 * Explicit translator implementations must implement the default constructor and should not
 * instantiate Language, AddressSpace, AddressFactory or Register objects until isValid() is invoked.
 */
public interface LanguageTranslator extends ExtensionPoint {
	
	/**
	 * Validate translator to complete initialization and ensure language compatibility.
	 * This method will be invoked by the LanguageTranslatorFactory before handing out this
	 * translator.
	 * @return true if translator successfully validated
	 */
	public boolean isValid();
	
	/**
	 * Returns old language
	 * @throws IllegalStateException if instance has not been validated
	 * @see #isValid()
	 */
	public Language getOldLanguage();

	/**
	 * Returns new language
	 */
	public Language getNewLanguage();
	
	/**
	 * Returns old language name
	 */
	public LanguageID getOldLanguageID();
	
	/**
	 * Returns new language name
	 */
	public LanguageID getNewLanguageID();
	
	/**
	 * Returns old language version
	 */
	public int getOldVersion();
	
	/**
	 * Returns new language version
	 */
	public int getNewVersion();
	
	/**
	 * Translate BASE address spaces (Overlay spaces are not handled)
	 * @param oldSpaceName old space name
	 * @return corresponding address space in new language
	 */
	public AddressSpace getNewAddressSpace(String oldSpaceName);

	/**
	 * Get the old register at the specified oldAddr.  This will null if the specified
	 * address is offcut within the register.
	 * The smallest register will be returned which is greater than or equal to the specified size.
	 * @param oldAddr old register address.
	 * @param size minimum register size
	 * @return old register or null if suitable register can not be found.
	 * @see #getOldRegisterContaining(Address) 
	 */
	public Register getOldRegister(Address oldAddr, int size);
	
	/**
	 * Get the largest old register which contains the specified oldAddr
	 * @param oldAddr old register address which may be offcut
	 * @return old register or null if suitable register can not be found.
	 */
	public Register getOldRegisterContaining(Address oldAddr);

	/**
	 * Returns the old processor context register or null if not defined
	 */
	public Register getOldContextRegister();
	
	/**
	 * Find new register which corresponds to the specified old register.
	 * @param oldReg old register
	 * @return new register or null if corresponding register not found.
	 */
	public Register getNewRegister(Register oldReg);
	
	/**
	 * Returns the new processor context register or null if not defined
	 */
	public Register getNewContextRegister();

	/**
	 * Get the translated register value
	 * @param oldValue old register value (may not be null)
	 * @return new register value or null if register not mapped
	 * @see #isValueTranslationRequired(Register)
	 */
	public RegisterValue getNewRegisterValue(RegisterValue oldValue);

	/**
	 * Returns true if register value translation required for 
	 * program context.
	 * @param oldReg
	 * @see #getNewRegisterValue(RegisterValue)
	 */
	public boolean isValueTranslationRequired(Register oldReg);

	/**
	 * Obtain the new compiler specification ID given the old compiler spec ID.
	 * @param oldCompilerSpecID old compiler spec ID.
	 * @return new compiler spec ID.
	 */
	public CompilerSpecID getNewCompilerSpecID(CompilerSpecID oldCompilerSpecID);

	/**
	 * Get a compiler spec suitable for use with the old language.  The compiler 
	 * spec returned is intended for upgrade use only prior to the setLanguage
	 * and may be based upon compiler conventions specified in the new compiler 
	 * spec returned by getNewCompilerSpec given the same compilerSpecID.
	 * @param oldCompilerSpecID old compiler spec ID.
	 * @return compiler spec for use with old language
	 * @throws CompilerSpecNotFoundException if new compiler spec not found based upon 
	 * translator mappings.
	 */
	public CompilerSpec getOldCompilerSpec(CompilerSpecID oldCompilerSpecID) throws CompilerSpecNotFoundException;

	/**
	 * Invoked after Program language upgrade has completed.  
	 * Implementation of this method permits the final re-disassembled program to be
	 * examined/modified to address more complex language upgrades.  This method will only be 
	 * invoked on the latest translator, which means all complex multi-version post-upgrade
	 * concerns must factor in the complete language transition.  The program's language 
	 * information will still reflect the original pre-upgrade state, and if the program is
	 * undergoing a schema version upgrade as well, certain complex upgrades may not
	 * have been completed (e.g., Function and Variable changes).  Program modifications should
	 * be restricted to instruction and instruction context changes only.
	 * @param program 
	 * @param oldLanguage the oldest language involved in the current upgrade translation
	 * (this is passed since this is the only fixup invocation which must handle the any
	 * relevant fixup complexities when transitioning from the specified oldLanguage).
	 * @param monitor task monitor
	 * @throws Exception if a bad exception occurs with the post upgrade fixup
	 * @throws CancelledException if upgrade cancelled
	 */
	public void fixupInstructions(Program program, Language oldLanguage, TaskMonitor monitor)
			throws Exception, CancelledException;
}
