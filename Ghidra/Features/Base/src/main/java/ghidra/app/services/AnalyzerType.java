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
package ghidra.app.services;

/**
 * AnalyzerType defines various types of analyzers that Ghidra provides.
 *
 * Analyzers get kicked off based on certain events or conditions, such
 * as a function being defined at a location.  Currently there are four types (although
 * only three are used, Data really has no analyzers yet).
 * 
 *    BYTES - analyze anywhere defined bytes are present (block of memory added)
 *    INSTRUCTIONS - analyze anywhere instructions are defined
 *    FUNCTIONS - analyze where a function is defined
 *    FUNCTION-MODIFIERS - analyze functions whose modifiers have changed
 *        modifiers include:
 *          - FUNCTION_CHANGED_THUNK
 * 		    - FUNCTION_CHANGED_INLINE
 * 			- FUNCTION_CHANGED_NORETURN
 * 			- FUNCTION_CHANGED_CALL_FIXUP
 * 			- FUNCTION_CHANGED_PURGE
 *    FUNCTION-SIGNATURES - analyze functions whose signatures have changed
 *    	  signature include:
 * 			- FUNCTION_CHANGED_PARAMETERS
 * 			- FUNCTION_CHANGED_RETURN
 *    DATA - analyze where data has been defined.
 * 
 * An analyzer can be kicked off because something has caused a change to program,
 * such as adding a function.  They can also be kicked off because a specific
 * area of the program has been requested to be analyzed by the user.
 * 
 */
public enum AnalyzerType {
	BYTE_ANALYZER("Byte Analyzer", "Triggered when bytes are added (memory block added)."),
	INSTRUCTION_ANALYZER("Instructions Analyzer", "Triggered when instructions are created."),
	FUNCTION_ANALYZER("Function Analyzer", "Triggered when functions are created."),
	FUNCTION_MODIFIERS_ANALYZER("Function-modifiers Analyzer", "Triggered when a function's modifier changes"),
	FUNCTION_SIGNATURES_ANALYZER("Function-Signatures Analyzer", "Triggered when a function's signature changes."),
	DATA_ANALYZER("Data Analyzer", "Triggered when data is created.");
	// TODO: Add Symbol analyzer type
	// SYMBOL_ANALYZER("Symbol Analyzer", "Triggered when non-default primary symbol is added or changed"),

	private String name;
	private String description;

	private AnalyzerType(String name, String description) {
		this.name = name;
		this.description = description;
	}

	/**
	 * Return the name of this AnalyzerType. 
	 */
	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	@Override
	public String toString() {
		return name;
	}

}
