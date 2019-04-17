/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.io.IOException;

/**
 * Exception class used when the named language cannot be found.
 */
public class LanguageNotFoundException extends IOException {

	/**
	 * Newer version of language required
	 * @param languageID
	 * @param majorVersion
	 * @param minorVersion
	 */
	public LanguageNotFoundException(LanguageID languageID, int majorVersion, int minorVersion) {
		super("Language version (V" + majorVersion + "." + minorVersion +
			" or later) required for '" + languageID + "'");
	}

	/**
	 * Language not found
	 * @param languageID
	 */
	public LanguageNotFoundException(LanguageID languageID) {
		super("Language not found for '" + languageID + "'");
	}

	public LanguageNotFoundException(String message) {
		super(message);
	}

	public LanguageNotFoundException(LanguageID languageID, CompilerSpecID compilerSpecID) {
		super("Language/Compiler Spec not found for '" + languageID + '/' + compilerSpecID + "'");
	}

	/**
	 * Language not found
	 * @param languageID
	 * @param msg
	 */
	public LanguageNotFoundException(LanguageID languageID, String msg) {
		super("Language not found for '" + languageID + "' " + msg);
	}

	public LanguageNotFoundException(Processor processor) {
		super("Language not found for processor: " + processor.toString());
	}
}
