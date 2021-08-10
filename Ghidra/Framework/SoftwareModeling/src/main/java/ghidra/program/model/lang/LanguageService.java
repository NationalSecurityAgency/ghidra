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

import java.util.List;

/**
 * Service that provides a Language given a name, and 
 * information about the language. 
 */
public interface LanguageService {

	/**
	 * Returns the language with the given language ID
	 * @param languageID the ID of language to retrieve
	 * @return the {@link Language} matching the given ID
	 * @throws LanguageNotFoundException if no language can be found for the given ID
	 */
	Language getLanguage(LanguageID languageID) throws LanguageNotFoundException;
	
	/** 
	 * Returns the default Language to use for the given processor;
	 * @param processor the processor for which to get a language.
	 * @throws LanguageNotFoundException if there is no languages at all for the given processor.
	 */
	Language getDefaultLanguage(Processor processor) throws LanguageNotFoundException;

	/**
	 * Get language information for the given language ID.
	 * @param languageID the id for the language.
	 * @return language information for the given language ID.
	 * @throws LanguageNotFoundException if there is no language for the given ID.
	 */
	LanguageDescription getLanguageDescription(LanguageID languageID)
			throws LanguageNotFoundException;

	/**
	 * Returns all known language Descriptions
	 * @param includeDeprecatedLanguages TODO
	 * @return all know language Descriptions.
	 */
	List<LanguageDescription> getLanguageDescriptions(boolean includeDeprecatedLanguages);

	/**
	 * Returns all known language descriptions which satisfy the criteria identify by the
	 * non-null parameters.  A null value implies a don't-care wildcard value.
	 * @param processor the processor for which to get a language
	 * @param endianess big or little
	 * @param size processor address space size (in bits)
	 * @param variant the processor version (usually 'default')
	 * @return the language descriptions that fit the parameters
	 * @deprecated use {@link #getLanguageDescriptions(Processor)} instead
	 */
	@Deprecated
	List<LanguageDescription> getLanguageDescriptions(Processor processor, Endian endianess,
			Integer size, String variant);

	/**
	 * Returns all known language/compiler spec pairs which satisfy the criteria
	 * identify by the non-null parameters. A null value implies a don't-care
	 * wildcard value.  OMITS DEPRECATED LANGUAGES.
	 * @param query TODO
	 * @return
	 */
	List<LanguageCompilerSpecPair> getLanguageCompilerSpecPairs(LanguageCompilerSpecQuery query);

	/**
	 * Returns all known language/compiler spec pairs which satisfy the criteria
	 * identify by the non-null parameters. A null value implies a don't-care
	 * wildcard value.  OMITS DEPRECATED LANGUAGES.
	 * This uses an ExternalLanguageCompilerSpecQuery rather than a
	 * LanguageCompilerSpecQuery.
	 * @param query
	 * @return
	 */
	List<LanguageCompilerSpecPair> getLanguageCompilerSpecPairs(
			ExternalLanguageCompilerSpecQuery query);

	/**
	 * Returns all language Descriptions associated with the given processor.
	 * @param processor the processor for which to retrieve all know language descriptions.
	 */
	List<LanguageDescription> getLanguageDescriptions(Processor processor);
}
