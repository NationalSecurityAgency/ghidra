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

/**
 * Service that provides a Language given a name, and 
 * information about the language. 
 */
public interface VersionedLanguageService extends LanguageService {

	/**
	 * Returns a specific language version with the given language ID.
	 * This form should only be used when handling language upgrade concerns.
	 * @param languageID the ID of language to retrieve.
	 * @param version major version
	 * @throws LanguageNotFoundException if the specified language version can not be found 
	 * for the given ID.
	 */
	Language getLanguage(LanguageID languageID, int version) throws LanguageNotFoundException;

	/**
	 * Get language information for a specific version of the given language ID.
	 * This form should only be used when handling language upgrade concerns.
	 * @param languageID the id for the language.
	 * @return language information for the given language ID.
	 * @throws LanguageNotFoundException if there is no language for the given ID.
	 */
	LanguageDescription getLanguageDescription(LanguageID languageID, int version)
			throws LanguageNotFoundException;

}
