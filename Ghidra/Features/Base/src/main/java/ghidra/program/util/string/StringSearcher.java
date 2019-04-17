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

public class StringSearcher extends AbstractStringSearcher {

	private boolean requireNullTermination;

	public StringSearcher(Program program, int minimumStringSize, int alignment,
			boolean allCharSizes, boolean requireNullTermination) {
		super(program, new AsciiCharSetRecognizer(), minimumStringSize, alignment, true,
			shouldLookForUTF16(program, allCharSizes), shouldLookForUTF32(program, allCharSizes));
		this.requireNullTermination = requireNullTermination;
	}

	public StringSearcher(Program program, CharSetRecognizer charSet, int minimumStringSize,
			int alignment, boolean allCharSizes, boolean requireNullTermination) {
		super(program, charSet, minimumStringSize, alignment, true,
			shouldLookForUTF16(program, allCharSizes), shouldLookForUTF32(program, allCharSizes));
		this.requireNullTermination = requireNullTermination;

	}

	private static boolean shouldLookForUTF32(Program program, boolean allCharSizes) {
		int wideCharSize = program.getDataTypeManager().getDataOrganization().getWideCharSize();
		return allCharSizes || wideCharSize == 4;
	}

	private static boolean shouldLookForUTF16(Program program, boolean allCharSizes) {
		int wideCharSize = program.getDataTypeManager().getDataOrganization().getWideCharSize();
		return allCharSizes || wideCharSize == 2;
	}

	@Override
	protected void processSequence(FoundStringCallback callback, Sequence sequence, MemBuffer buf) {
		if (requireNullTermination && !sequence.isNullTerminated()) {
			return;
		}
		callback.stringFound(getFoundString(buf, sequence, sequence.getStringDataType()));
	}
}
