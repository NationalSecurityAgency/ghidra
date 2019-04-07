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

import java.util.Collection;
import java.util.List;

public interface LanguageDescription {
	public LanguageID getLanguageID();

	public Processor getProcessor();

	public Endian getEndian();

	public Endian getInstructionEndian();

	public int getSize();

	public String getVariant();

	public int getVersion();

	public int getMinorVersion();

	public String getDescription();

	public boolean isDeprecated();

	public Collection<CompilerSpecDescription> getCompatibleCompilerSpecDescriptions();

	public CompilerSpecDescription getCompilerSpecDescriptionByID(CompilerSpecID compilerSpecID)
			throws CompilerSpecNotFoundException;

	/**
	 * Returns external names for this language associated with other tools.  For example, x86
	 * languages are usually referred to as "metapc" by IDA-PRO.  So, getExternalNames("IDA-PRO")
	 * will return "metapc" for most x86 languages.
	 *
	 * @param externalTool external tool for looking up external tool names
	 * @return external names for this language associated with tool 'key' -- null if there are no results
	 */
	public List<String> getExternalNames(String externalTool);
}
