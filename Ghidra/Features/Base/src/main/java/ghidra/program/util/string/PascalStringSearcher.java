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
package ghidra.program.util.string;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.ascii.*;

public class PascalStringSearcher extends AbstractStringSearcher {

	public PascalStringSearcher(Program program, int minimumStringSize, int alignment,
			boolean includePascalUnicode) {
		super(program, new AsciiCharSetRecognizer(), minimumStringSize, alignment, true,
			checkForWideChar(program), false);
	}

	public PascalStringSearcher(Program program, CharSetRecognizer charSet, int minimumStringSize,
			int alignment, boolean includePascalUnicode) {
		super(program, charSet, minimumStringSize, alignment, true, checkForWideChar(program),
			false);
	}

	private static boolean checkForWideChar(Program program) {
		int wideCharSize = program.getDataTypeManager().getDataOrganization().getWideCharSize();
		return wideCharSize == 2;
	}

	@Override
	protected void processSequence(FoundStringCallback callback, Sequence sequence, MemBuffer buf) {

		Sequence pascalSequence = PascalUtil.findPascalSequence(buf, sequence, getAlignment());
		if (pascalSequence != null) {
			callback.stringFound(
				getFoundString(buf, pascalSequence, pascalSequence.getStringDataType()));
		}

	}

}
