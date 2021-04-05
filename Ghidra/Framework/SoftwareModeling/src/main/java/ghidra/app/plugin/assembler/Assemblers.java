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

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.assembler.sleigh.SleighAssemblerBuilder;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;

/**
 * The primary class for obtaining an {@link Assembler} for a Ghidra-supported language.
 * 
 * <p>
 * The general flow is: First, obtain an assembler for a language or program. Second, call its
 * {@link Assembler#assemble(Address, String...)} and related methods to perform assembly. More
 * advanced uses pass a {@link AssemblySelector} to control certain aspects of assembly instruction
 * selection, and to obtain advanced diagnostics, like detailed errors and code completion.
 * 
 * <pre>
 * Assembler asm = Assemblers.getAssembler(currentProgram);
 * asm.assemble(currentAddress, "ADD ...");
 * </pre>
 */
public final class Assemblers {
	private static Map<LanguageID, AssemblerBuilder> builders = new HashMap<>();

	/**
	 * Get a builder for the given language, possibly using a cached one.
	 * 
	 * @param lang the language
	 * @return the builder for that language, if successful
	 */
	protected static AssemblerBuilder getBuilderForLang(Language lang) {
		AssemblerBuilder ab = builders.get(lang.getLanguageID());
		if (ab != null) {
			return ab;
		}
		if (lang instanceof SleighLanguage) {
			ab = new SleighAssemblerBuilder((SleighLanguage) lang);
			builders.put(lang.getLanguageID(), ab);
			return ab;
		}
		throw new UnsupportedOperationException("Unsupported language type: " + lang.getClass());
	}

	/**
	 * Get an assembler for the given program.
	 * 
	 * <p>
	 * Provides an assembler suitable for the program's language, and bound to the program. Calls to
	 * its Assembler#assemble() function will cause modifications to the bound program. If this is
	 * the first time an assembler for the program's language has been requested, this function may
	 * take some time to build the assembler.
	 * 
	 * @param selector a method to select a single result from many
	 * @param program the program for which an assembler is requested
	 * @return the assembler bound to the given program
	 */
	public static Assembler getAssembler(Program program, AssemblySelector selector) {
		AssemblerBuilder b = getBuilderForLang(program.getLanguage());
		return b.getAssembler(selector, program);
	}

	/**
	 * Get an assembler for the given language.
	 * 
	 * <p>
	 * Provides a suitable assembler for the given language. Only calls to its
	 * Assembler#assembleLine() method are valid. If this is the first time a language has been
	 * requested, this function may take some time to build the assembler. Otherwise, it returns a
	 * cached assembler.
	 * 
	 * @param selector a method to select a single result from many
	 * @param lang the language for which an assembler is requested
	 * @return the assembler for the given language
	 */
	public static Assembler getAssembler(Language lang, AssemblySelector selector) {
		AssemblerBuilder b = getBuilderForLang(lang);
		return b.getAssembler(selector);
	}

	/**
	 * Get an assembler for the given program.
	 * 
	 * @see #getAssembler(Program, AssemblySelector)
	 * 
	 * @param program the program
	 * @return a suitable assembler
	 */
	public static Assembler getAssembler(Program program) {
		return getAssembler(program, new AssemblySelector());
	}

	/**
	 * Get an assembler for the given language.
	 * 
	 * @see #getAssembler(Language, AssemblySelector)
	 * 
	 * @param lang the language
	 * @return a suitable assembler
	 */
	public static Assembler getAssembler(Language lang) {
		return getAssembler(lang, new AssemblySelector());
	}
}
