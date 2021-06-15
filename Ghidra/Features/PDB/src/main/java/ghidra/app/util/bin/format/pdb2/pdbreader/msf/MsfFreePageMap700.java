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
package ghidra.app.util.bin.format.pdb2.pdbreader.msf;

import java.io.IOException;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class is the version of {@link AbstractMsfFreePageMap} for Microsoft v7.00 Free Page Map.
 */
class MsfFreePageMap700 extends AbstractMsfFreePageMap {

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Constructor.
	 * @param msf The {@link AbstractMsf} to which this class belongs.
	 */
	MsfFreePageMap700(AbstractMsf msf) {
		super(msf);
	}

	@Override
	boolean isBig() {
		return true;
	}

	@Override
	void deserialize(TaskMonitor monitor) throws IOException, CancelledException {
		// Calculate the number of pages that the FreePageMap occupies on disk.
		int log2BitsPerPage = msf.getLog2PageSize() + 3; // 3 = log2(bitsperbyte)
		long freePageMapNumPages =
			AbstractMsf.floorDivisionWithLog2Divisor(msf.getNumPages(), log2BitsPerPage);

		// Get the First page number of the FreePageMap on disk.
		int nextPageNumber = msf.getCurrentFreePageMapFirstPageNumber();

		// Read the FreePageMap, which is dispersed across the file (see note below).
		MsfFileReader fileReader = msf.fileReader;
		int pageSize = msf.getPageSize();
		while (freePageMapNumPages > 0) {
			monitor.checkCanceled();
			byte[] bytes = new byte[pageSize];
			fileReader.read(nextPageNumber, 0, pageSize, bytes, 0);
			addMap(bytes, monitor);
			freePageMapNumPages--;
			// This is correct.  Each page of the FreePageMap700 is located at pageSize number
			//  of pages away from the last page.  So if the first page of the FreePageMap700
			//  is page 1, and if the pageSize is 4096, then the next page used as part of
			//  the FreePageMap700 is page 4097.  FreePageMap200 is different in that its data
			//  resides sequentially on disk.
			nextPageNumber += pageSize;
		}
	}
}
