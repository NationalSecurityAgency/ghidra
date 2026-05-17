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
package ghidra.app.util.sourcelanguage;

import java.util.List;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.task.TaskMonitor;

/**
 * An {@link ExtensionPoint} to dynamically support source language-specific 
 * {@link SpecExtension spec extensions}
 */
public interface SourceLanguageSpecExtension extends ExtensionPoint {

	/**
	 * Processor-related attributes that form conditions for applying the given spec extension
	 * contents to a program
	 * 
	 * @param processor The name of the processor (required)
	 * @param endian The processor endianness ("little" or "big") (could be empty/null for wildcard)
	 * @param size The processor size (i.e., "32, "64", etc) (could be empty/null for wildcard)
	 * @param variant The processor variant (could be empty/null for wildcard)
	 * @param formats The names of the supported binary file formats (could be empty/null for 
	 *   wildcard)
	 * @param contents The contents of the {@link SpecExtension}, which is currently always XML
	 */
	public record SpecExtensionRule(String processor, String endian, String size, String variant,
			List<String> formats, String contents) {}

	/**
	 * {@return the {@link SourceLanguageID} of the source language this 
	 * {@link SourceLanguageSpecExtension} is compatible with}
	 */
	public SourceLanguageID getCompatibleSourceLanguage();

	/**
	 * {@return the source language's {@link SpecExtensionRule}s}
	 * 
	 * @param program The {@link Program}
	 * @param log The error log
	 * @param monitor The {@link TaskMonitor}
	 */
	public List<SpecExtensionRule> getSpecExtensionRules(Program program, MessageLog log,
			TaskMonitor monitor);
}
