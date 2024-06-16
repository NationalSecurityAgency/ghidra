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
package ghidra.file.formats.squashfs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class SquashFragment {

	// Offset within the archive where the fragment starts
	private final long fragmentOffset;

	// Header for the fragment which contains two fields:
	// isCompressed - If the 1 << 24 bit is cleared, the fragment is compressed
	// fragmentSize   - The size of the fragment in bytes (lower 24 bits)
	private final int header;

	// This field is unused as of 4.0
	private final int unusedField;

	/**
	 * Represents a SquashFS fragment
	 * @param reader A binary reader with pointer index at the start of the fragment data
	 * @throws IOException Any read operation failure
	 */
	public SquashFragment(BinaryReader reader) throws IOException {

		fragmentOffset = reader.readNextLong();

		// The next integer contains both size and compression info to be masked out
		header = reader.readNextInt();

		// Check if the unused value is zero and warn the user if it isn't
		unusedField = reader.readNextInt();

	}

	public long getFragmentOffset() {
		return fragmentOffset;
	}

	public boolean isCompressed() {
		return (header & SquashConstants.FRAGMENT_COMPRESSED_MASK) == 0;
	}

	public long getFragmentSize() {
		return header & ~SquashConstants.FRAGMENT_COMPRESSED_MASK;
	}

	public int getUnusedField() {
		if (unusedField != 0) {
			Msg.warn(this, "Fragment has non-zero \"unused\" field");
		}
		return unusedField;
	}
}
