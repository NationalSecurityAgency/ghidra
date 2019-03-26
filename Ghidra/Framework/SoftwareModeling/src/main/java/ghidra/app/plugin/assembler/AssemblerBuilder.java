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
package ghidra.app.plugin.assembler;

import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;

/**
 * An interface to build an assembler for a given language
 */
public interface AssemblerBuilder {
	/**
	 * Get the ID of the language for which this instance builds an assembler
	 * @return the language ID
	 */
	public LanguageID getLanguageID();

	/**
	 * Get the language for which this instance builds an assembler
	 * @return the language
	 */
	public Language getLanguage();

	/**
	 * Build an assembler with the given selector callback
	 * @param selector the selector callback
	 * @return the built assembler
	 */
	public Assembler getAssembler(AssemblySelector selector);

	/**
	 * Build an assembler with the given selector callback and program binding
	 * @param selector the selector callback
	 * @param program the bound program
	 * @return the built assembler
	 */
	public Assembler getAssembler(AssemblySelector selector, Program program);
}
