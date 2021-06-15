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
 * This class is the version of {@link AbstractMsfFreePageMap} for Microsoft v2.00 Free Page Map.
 */
class MsfFreePageMap200 extends AbstractMsfFreePageMap {

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Constructor.
	 * @param msf The {@link AbstractMsf} to which this class belongs.
	 */
	MsfFreePageMap200(AbstractMsf msf) {
		super(msf);
	}

	@Override
	boolean isBig() {
		return false;
	}

	@Override
	void deserialize(TaskMonitor monitor) throws IOException, CancelledException {
		int size = msf.getNumSequentialFreePageMapPages() * msf.getPageSize();
		byte[] bytes = new byte[size];
		MsfFileReader fileReader = msf.fileReader;
		fileReader.read(msf.getCurrentFreePageMapFirstPageNumber(), 0, size, bytes, 0);
		addMap(bytes, monitor);
	}

}
