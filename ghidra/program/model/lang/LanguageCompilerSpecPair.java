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

import ghidra.program.util.DefaultLanguageService;

/**
 * Represents an opinion's processor language and compiler.
 * 
 * @see LanguageID
 * @see CompilerSpecID
 */
public final class LanguageCompilerSpecPair implements Comparable<LanguageCompilerSpecPair> {

	public final LanguageID languageID;
	public final CompilerSpecID compilerSpecID;

	/**
	 * Creates a new language and compiler pair.
	 * 
	 * @param languageID The language ID string (x86:LE:32:default, 8051:BE:16:default, etc).
	 * @param compilerSpecID The compiler spec ID string (gcc, borlandcpp, etc).
	 * @throws IllegalArgumentException if the language or compiler ID strings are null or empty.
	 */
	public LanguageCompilerSpecPair(String languageID, String compilerSpecID) {
		if (languageID == null) {
			throw new IllegalArgumentException("languageID == null not allowed");
		}
		if (compilerSpecID == null) {
			throw new IllegalArgumentException("compilerSpecID == null not allowed");
		}
		if ("".equals(languageID)) {
			throw new IllegalArgumentException("empty languageID not allowed");
		}
		if ("".equals(compilerSpecID)) {
			throw new IllegalArgumentException("empty compilerSpecID not allowed");
		}
		this.languageID = new LanguageID(languageID);
		this.compilerSpecID = new CompilerSpecID(compilerSpecID);
	}

	/**
	 * Creates a new language and compiler pair.
	 * 
	 * @param languageID The language ID.
	 * @param compilerSpecID The compiler spec ID.
	 * @throws IllegalArgumentException if the language or compiler ID is null.
	 */
	public LanguageCompilerSpecPair(LanguageID languageID, CompilerSpecID compilerSpecID) {
		if (languageID == null) {
			throw new IllegalArgumentException("languageID == null not allowed");
		}
		if (compilerSpecID == null) {
			throw new IllegalArgumentException("compilerSpecID == null not allowed");
		}
		this.languageID = languageID;
		this.compilerSpecID = compilerSpecID;
	}

	/**
	 * Gets the {@link Language} for this object's {@link LanguageID}.
	 * 
	 * @return The {@link Language} for this object's {@link LanguageID}.
	 * @throws LanguageNotFoundException if no {@link Language} could be found for this
	 *   object's {@link LanguageID}.
	 */
	public Language getLanguage() throws LanguageNotFoundException {
		return DefaultLanguageService.getLanguageService().getLanguage(languageID);
	}

	/**
	 * Gets the {@link CompilerSpec} for this object's {@link CompilerSpecID}.
	 * 
	 * @return The {@link CompilerSpec} for this object's {@link CompilerSpecID}.
	 * @throws LanguageNotFoundException if no {@link Language} could be found for this
	 *   object's {@link LanguageID}.
	 * @throws CompilerSpecNotFoundException if no {@link CompilerSpec} could be found for this
	 *   object's {@link CompilerSpecID}.
	 */
	public CompilerSpec getCompilerSpec()
			throws CompilerSpecNotFoundException, LanguageNotFoundException {
		return getLanguage().getCompilerSpecByID(compilerSpecID);
	}

	/**
	 * Gets the {@link Language} for this object's {@link LanguageID}, using the given language
	 * service to do the lookup.
	 * 
	 * @param languageService The language service to use for language lookup.
	 * @return The {@link Language} for this object's {@link LanguageID}, using the given language
	 *   service to do the lookup.
	 * @throws LanguageNotFoundException if no {@link Language} could be found for this
	 *   object's {@link LanguageID} using the given language service.
	 */
	public Language getLanguage(LanguageService languageService) throws LanguageNotFoundException {
		return languageService.getLanguage(languageID);
	}

	/**
	 * Gets the {@link CompilerSpec} for this object's {@link CompilerSpecID}, using the given
	 * language service to do the lookup.
	 * 
	 * @param languageService The language service to use for compiler lookup.
	 * @return The {@link CompilerSpec} for this object's {@link CompilerSpecID}, using the given 
	 *   language service to do the lookup.
	 * @throws LanguageNotFoundException if no {@link Language} could be found for this
	 *   object's {@link LanguageID} using the given language service.
	 * @throws CompilerSpecNotFoundException if no {@link CompilerSpec} could be found for this
	 *   object's {@link CompilerSpecID} using the given language service.
	 */
	public CompilerSpec getCompilerSpec(LanguageService languageService)
			throws CompilerSpecNotFoundException, LanguageNotFoundException {
		return getLanguage(languageService).getCompilerSpecByID(compilerSpecID);
	}

	/**
	 * Gets the {@link LanguageDescription} for this object's {@link LanguageID}.
	 * 
	 * @return The {@link LanguageDescription} for this object's {@link LanguageID}.
	 * @throws LanguageNotFoundException if no {@link LanguageDescription} could be found for this
	 *   object's {@link LanguageID}.
	 */
	public LanguageDescription getLanguageDescription() throws LanguageNotFoundException {
		return DefaultLanguageService.getLanguageService().getLanguageDescription(languageID);
	}

	/**
	 * Gets the {@link CompilerSpecDescription} for this object's {@link CompilerSpecID}.
	 * 
	 * @return The {@link CompilerSpecDescription} for this object's {@link CompilerSpecID}.
	 * @throws LanguageNotFoundException if no {@link LanguageDescription} could be found for this
	 *   object's {@link LanguageID}.
	 * @throws CompilerSpecNotFoundException if no {@link CompilerSpecDescription} could be found 
	 *   for this object's {@link CompilerSpecID}.
	 */
	public CompilerSpecDescription getCompilerSpecDescription()
			throws LanguageNotFoundException, CompilerSpecNotFoundException {
		return getLanguageDescription().getCompilerSpecDescriptionByID(compilerSpecID);
	}

	/**
	 * Gets the {@link LanguageDescription} for this object's {@link LanguageID}.
	 * 
	 * @param languageService The language service to use for description lookup.
	 * @return The {@link LanguageDescription} for this object's {@link LanguageID}.
	 * @throws LanguageNotFoundException if no {@link LanguageDescription} could be found for this
	 *   object's {@link LanguageID} using the given language service.
	 */
	public LanguageDescription getLanguageDescription(LanguageService languageService)
			throws LanguageNotFoundException {
		return languageService.getLanguageDescription(languageID);
	}

	/**
	 * Gets the {@link CompilerSpecDescription} for this object's {@link CompilerSpecID}.
	 * 
	 * @param languageService The language service to use for description lookup.
	 * @return The {@link CompilerSpecDescription} for this object's {@link CompilerSpecID}.
	 * @throws LanguageNotFoundException if no {@link LanguageDescription} could be found for this
	 *   object's {@link LanguageID}.
	 * @throws CompilerSpecNotFoundException if no {@link CompilerSpecDescription} could be found 
	 *   for this object's {@link CompilerSpecID} using the given language service.
	 */
	public CompilerSpecDescription getCompilerSpecDescription(LanguageService languageService)
			throws LanguageNotFoundException, CompilerSpecNotFoundException {
		return getLanguageDescription(languageService).getCompilerSpecDescriptionByID(
			compilerSpecID);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((compilerSpecID == null) ? 0 : compilerSpecID.hashCode());
		result = prime * result + ((languageID == null) ? 0 : languageID.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof LanguageCompilerSpecPair)) {
			return false;
		}
		final LanguageCompilerSpecPair other = (LanguageCompilerSpecPair) obj;
		if (compilerSpecID == null) {
			if (other.compilerSpecID != null) {
				return false;
			}
		}
		else if (!compilerSpecID.equals(other.compilerSpecID)) {
			return false;
		}
		if (languageID == null) {
			if (other.languageID != null) {
				return false;
			}
		}
		else if (!languageID.equals(other.languageID)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return languageID + ":" + compilerSpecID;
	}

	@Override
	public int compareTo(LanguageCompilerSpecPair o) {
		int result = languageID.compareTo(o.languageID);
		if (result == 0) {
			result = compilerSpecID.compareTo(o.compilerSpecID);
		}
		return result;
	}
}
