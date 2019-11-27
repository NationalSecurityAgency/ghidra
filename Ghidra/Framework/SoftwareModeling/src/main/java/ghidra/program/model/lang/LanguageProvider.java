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

import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL LanguageProvider CLASSES MUST END IN "LanguageProvider".  If not,
 * the ClassSearcher will not find them.
 * 
 * Service for providing languages.
 *
 */
public interface LanguageProvider extends ExtensionPoint {

	/**
	 * Returns the language with the given name or null if no language has that name
	 * 
	 * @param languageId the name of the language to be retrieved
	 * @return the {@link Language} with the given name
	 */
	Language getLanguage(LanguageID languageId);

	/**
	 * Returns a list of language descriptions provided by this provider
	 */
	LanguageDescription[] getLanguageDescriptions();

	/**
	 * @return true if one of more languages or language description failed to load
	 * properly.
	 */
	boolean hadLoadFailure();

	/**
	 * Returns true if the given language has been successfully loaded
	 * 
	 * @param languageId the name of the language to be retrieved
	 * @return true if the given language has been successfully loaded
	 */
	boolean isLanguageLoaded(LanguageID languageId);
}
