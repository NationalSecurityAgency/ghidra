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

import ghidra.program.disassemble.Disassembler;

public final class GhidraLanguagePropertyKeys {
	private GhidraLanguagePropertyKeys() {
	}

	/**
	 * CUSTOM_DISASSEMBLER_CLASS is a full class name for a language-specific
	 * disassembler implementation.  The specified class must extend the generic 
	 * disassembler {@link Disassembler} implementation and must implement the same
	 * set of constructors.
	 */
	public static final String CUSTOM_DISASSEMBLER_CLASS = "customDisassemblerClass";

	/**
	 * ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS is a boolean property used to
	 * indicate if function bodies can actually start offcut. This is useful,
	 * for instance, with the ARM processor in THUMB mode since the least
	 * significant bit of the address is 0x1 for a THUMB mode function, even
	 * though outside references to this function will be at one byte less than
	 * the actual function start. Default is false.
	 */
	public static final String ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS =
		"allowOffcutReferencesToFunctionStarts";

	/**
	 * USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES is a boolean property that
	 * indicates if a language should use the switch table analysis in the
	 * OperandReferenceAnalyzer. Default is false.
	 */
	public static final String USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES =
		"useOperandReferenceAnalyzerSwitchTables";

	/**
	 * IS_TMS320_FAMILY is a boolean property that indicates this language is
	 * part of the general TMS320 family. Default is false. Used for general
	 * TMS320 analysis.
	 */
	public static final String IS_TMS320_FAMILY = "isTMS320Family";

	/**
	 * PARALLEL_INSTRUCTION_HELPER_CLASS is a full class name for an implementation
	 * of the ParallelInstructionLanguageHelper.  Those languages which support parallel
	 * instruction execution may implement this helper class to facilitate display of
	 * a || indicator within a listing view.
	 */
	public static final String PARALLEL_INSTRUCTION_HELPER_CLASS = "parallelInstructionHelperClass";

	/**
	 * ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE is a boolean property that
	 * indicates if addresses don't appear directly in code. Supposedly applies
	 * to all RISC processors, according to ScalarOperandAnalyzer. Default is
	 * false.
	 */
	public static final String ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE =
		"addressesDoNotAppearDirectlyInCode";

	/**
	 * USE_NEW_FUNCTION_STACK_ANALYSIS is a boolean property that indicates if
	 * the StackVariableAnalyzer should use a NewFunctionStackAnalysisCmd
	 * instead of the older FunctionStackAnalysisCmd. Default is false.
	 */
	public static final String USE_NEW_FUNCTION_STACK_ANALYSIS = "useNewFunctionStackAnalysis";

	/**
	 * EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS is a string property that indicates the
	 * classname of a EmulateInstructionStateModifier implementation which should be
	 * used during emulation to assist with the adjusting the emulator state before and/or after
	 * each instruction is executed.  This class may also provide language defined behaviors
	 * for custom pcodeop's.  Default is null.
	 */
	public static final String EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS =
		"emulateInstructionStateModifierClass";

	/**
	 * PCODE_INJECT_LIBRARY_CLASS indicates the classname of a PcodeInjectLibrary implementation
	 * that is used to generate p-code injection payloads which can replace either CALLs or CALLOTHERs
	 * during any form of p-code analysis.  The injections are primarily provided by {@code <callfixup>}
	 * and {@code <callotherfixup>} tags in the compiler spec, but this provides a hook point for
	 * providing other means of injection.
	 */
	public static final String PCODE_INJECT_LIBRARY_CLASS = "pcodeInjectLibraryClass";

	/**
	 * Shared return analysis, where at the end of one function, the code will jump to another, and use
	 * the jumped to subroutines return.  Shared Return analysis is enabled by default for all processors.
	 * 
	 * If calls are used as long-jumps this can cause problems, so it is disabled for older arm processors.
	 */
	public static final String ENABLE_SHARED_RETURN_ANALYSIS = "enableSharedReturnAnalysis";

	/**
	 * Non returning function analysis, where a function such as exit() is known to the compiler
	 * not to return.  The compiler will generate data or code for another function immediately
	 * following the call.  Non-returning functions can be detected in many cases.
	 */
	public static final String ENABLE_NO_RETURN_ANALYSIS = "enableNoReturnAnalysis";

	/**
	 * Property to indicate that all stored instruction context should be cleared
	 * during a language upgrade operation which requires redisassembly.
	 * NOTE: This is an experimental concept which may be removed in the future
	 */
	public static final String RESET_CONTEXT_ON_UPGRADE = "resetContextOnUpgrade";
	
	/**
	 * Property to indicate the minimum recommended base address within the default
	 * data space for placing relocatable data sections.  This is intended to 
	 * avoid loading into low memory regions where registers may be defined.
	 * The default value for ELF will be just beyond the last memory register defined
	 * within the default data space.  This option is only utilized by the
	 * ELF Loader for Harvard Architecures when loading a relocatable ELF binary
	 * (i.e., object module) and corresponds to the ELF Loader option: <code>Data Image Base</code>.
	 */
	public static final String MINIMUM_DATA_IMAGE_BASE = "minimumDataImageBase";
}
