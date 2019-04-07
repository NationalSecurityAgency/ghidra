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

import java.io.IOException;

/**
 * Exception class used when the named compiler spec cannot be found.
 */
public class CompilerSpecNotFoundException extends IOException {
	public CompilerSpecNotFoundException(LanguageID languageId, CompilerSpecID compilerSpecID) {
		super("Compiler Spec not found for '" + languageId + "/" + compilerSpecID + "'");
	}

	public CompilerSpecNotFoundException(LanguageID languageId, CompilerSpecID compilerSpecID, String resourceFileName,
			Throwable e) {
		super("Exception reading " + languageId + "/" + compilerSpecID + "(" + resourceFileName + "): " + e.getMessage(),
			e);
	}
}
