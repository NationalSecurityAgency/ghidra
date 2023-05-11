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

import javax.help.UnsupportedOperationException;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class is an extension of {@link Msf}, and has the sole purpose of stubbing the Msf for
 *  testing of internal components of PDB classes.
 */
public class StubMsf implements Msf {

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a basic object.
	 *  Note: not all values are initialized.  Constructor for a dummy MSF used for testing
	 */
	public StubMsf() {
	}

	@Override
	public void close() throws IOException {
		// Do nothing
	}

	@Override
	public String getFilename() {
		throw new UnsupportedOperationException();
	}

	@Override
	public TaskMonitor getMonitor() {
		return TaskMonitor.DUMMY;
	}

	@Override
	public void checkCancelled() throws CancelledException {
		TaskMonitor.DUMMY.checkCancelled();
	}

	@Override
	public int getPageSize() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getNumStreams() {
		throw new UnsupportedOperationException();
	}

	@Override
	public MsfStream getStream(int streamNumber) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MsfFileReader getFileReader() {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] getIdentification() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getPageSizeOffset() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void parseFreePageMapPageNumber(PdbByteReader reader) throws PdbException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void parseCurrentNumPages(PdbByteReader reader) throws PdbException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void create() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void configureParameters() throws PdbException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getPageNumberSize() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getLog2PageSize() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getPageSizeModMask() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getNumSequentialFreePageMapPages() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getHeaderPageNumber() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getDirectoryStreamNumber() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getNumPages() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getCurrentFreePageMapFirstPageNumber() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void deserialize() throws IOException, PdbException, CancelledException {
		throw new UnsupportedOperationException();
	}

}
