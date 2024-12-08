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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SquashFragmentTable {

	// A list of fragments within the archive
	private final List<SquashFragment> fragmentEntries;

	// The lowest fragment pointer in the archive. Used for locating the end of the directory table
	private long minFragPointer = Long.MAX_VALUE;

	/**
	 * Represents the fragment table within the SquashFS archive
	 * @param reader A binary reader for the entire SquashFS archive
	 * @param superBlock The SuperBlock for the current archive
	 * @param monitor Monitor to allow the user to cancel the load
	 * @throws IOException Any read operation failure
	 * @throws CancelledException The user cancelled the archive load
	 */
	public SquashFragmentTable(BinaryReader reader, SquashSuperBlock superBlock,
			TaskMonitor monitor) throws IOException, CancelledException {

		// Check if the user cancelled the load
		monitor.checkCancelled();

		// Read from the start of the directory table
		reader.setPointerIndex(superBlock.getFragmentTableStart());

		fragmentEntries = new ArrayList<SquashFragment>();

		// Based on the number of bytes all fragments in the archive take up, calculate the number
		// of indexes that the archive will have to those blocks
		long numFragments =
			((superBlock.getTotalFragments() * SquashConstants.FRAGMENT_ENTRY_LENGTH) +
				SquashConstants.MAX_UNIT_BLOCK_SIZE - 1) / SquashConstants.MAX_UNIT_BLOCK_SIZE;

		// Store the list of fragment pointers
		long[] fragmentPointers = reader.readNextLongArray((int) numFragments);

		// For each pointer to a fragment, move to that fragment and get the data from it
		for (int i = 0; i < fragmentPointers.length; i++) {

			// Check if the user cancelled the load
			monitor.checkCancelled();

			// Assign the smallest fragment pointer
			minFragPointer = Math.min(minFragPointer, fragmentPointers[i]);

			// Read from the start of the fragment
			reader.setPointerIndex(fragmentPointers[i]);

			// If needed, decompress the fragment
			byte[] uncompressedBytes =
				SquashUtils.decompressBlock(reader, superBlock.getCompressionType(), monitor);

			// This reader will only hold the uncompressed bytes
			BinaryReader fragmentReader = SquashUtils.byteArrayToReader(uncompressedBytes);

			// Add all fragments to the entry list
			while (fragmentReader.hasNext()) {

				// Check if the user cancelled the load
				monitor.checkCancelled();

				fragmentEntries.add(new SquashFragment(fragmentReader));
			}
		}
	}

	public List<SquashFragment> getFragments() {
		return fragmentEntries;
	}

	public SquashFragment getFragment(int index) {
		if (index >= 0 && index < fragmentEntries.size()) {
			return fragmentEntries.get(index);
		}
		return null;
	}

	public long getMinFragPointer() {
		return minFragPointer;
	}
}
