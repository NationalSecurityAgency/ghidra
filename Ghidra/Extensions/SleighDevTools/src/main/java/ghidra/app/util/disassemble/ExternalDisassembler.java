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
package ghidra.app.util.disassemble;

import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.classfinder.ExtensionPoint;

public interface ExternalDisassembler extends ExtensionPoint {

	public String getDisassembly(CodeUnit cu) throws Exception;

	public String getDisassemblyDisplayPrefix(CodeUnit cu) throws Exception;

	public String getDisassemblyOfBytes(Language language, boolean isBigEndian, long address,
			byte[] byteString) throws Exception;

	public boolean isSupportedLanguage(Language language);

	public void destroy();
}
