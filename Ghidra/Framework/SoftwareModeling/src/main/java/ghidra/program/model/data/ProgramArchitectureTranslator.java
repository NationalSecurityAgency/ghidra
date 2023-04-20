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
package ghidra.program.model.data;

import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.LanguageTranslatorAdapter;

public class ProgramArchitectureTranslator extends LanguageTranslatorAdapter {

	private CompilerSpec oldCompilerSpec;
	private CompilerSpec newCompilerSpec;

	public ProgramArchitectureTranslator(Language oldLanguage, CompilerSpecID oldCompilerSpecId,
			Language newLanguage, CompilerSpecID newCompilerSpecId)
			throws CompilerSpecNotFoundException, IncompatibleLanguageException {
		super(oldLanguage, newLanguage);
		if (!oldLanguage.getProcessor().equals(newLanguage.getProcessor())) {
			throw new IncompatibleLanguageException("Architecture processors differ: " +
				oldLanguage.getProcessor() + " vs " + newLanguage.getProcessor());
		}
		this.oldCompilerSpec = oldLanguage.getCompilerSpecByID(oldCompilerSpecId);
		this.newCompilerSpec = newLanguage.getCompilerSpecByID(newCompilerSpecId);
		validateDefaultSpaceMap();
	}

	public ProgramArchitectureTranslator(LanguageID oldLanguageId, int oldLanguageVersion,
			CompilerSpecID oldCompilerSpecId, Language newLanguage,
			CompilerSpecID newCompilerSpecId)
			throws LanguageNotFoundException, CompilerSpecNotFoundException,
			IncompatibleLanguageException {
		this(getLanguage(oldLanguageId, oldLanguageVersion), oldCompilerSpecId, newLanguage,
			newCompilerSpecId);
	}

	private static Language getLanguage(LanguageID languageId, int languageVersion)
			throws LanguageNotFoundException {
		Language language = DefaultLanguageService.getLanguageService().getLanguage(languageId);
		if (languageVersion > 0 && language.getVersion() != languageVersion) {
			throw new LanguageNotFoundException(
				"Language not found for '" + languageId + "' version " + languageVersion + ".x");
		}
		return language;
	}

	public CompilerSpec getOldCompilerSpec() {
		return oldCompilerSpec;
	}

	public CompilerSpec getNewCompilerSpec() {
		return newCompilerSpec;
	}


}
