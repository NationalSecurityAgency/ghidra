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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;

import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Parser for detecting the appropriate {@link PdbDebugInfo} format for the filename
 *  given.  It then creates and returns the appropriate {@link PdbDebugInfo} object.
 */
public class PdbDebugInfoParser {

	private static final int DATABASE_INTERFACE_STREAM_NUMBER = 3;

	//==============================================================================================
	public static final int DBIHDR700_SIG = 0xffffffff;
	public static final int DBI41_ID = 930803;  // 0x000e33f3
	public static final int DBI50_ID = 19960307;  // 0x013091f3
	public static final int DBI60_ID = 19970606;  // 0x0130ba2e
	public static final int DBI70_ID = 19990903;  // 0x01310977
	public static final int DBI110_ID = 20091201;  // 0x01329141

	//==============================================================================================
	private PdbByteReader debugReader;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Parses information to determine the version of Database Interface to create.
	 * @param pdb {@link AbstractPdb} that owns this Database Interface.
	 * @return {@link PdbDebugInfo} of the appropriate Database Interface or null if
	 *  the stream does not have enough information to be parsed.  
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon error in processing components.
	 */
	public PdbDebugInfo parse(AbstractPdb pdb) throws IOException, PdbException {
		PdbDebugInfo debugInfo;
		try {
			int streamNumber = getStreamNumber();
			// Only reading 8-bytes - no need for monitor
			PdbByteReader reader =
				pdb.getReaderForStreamNumber(streamNumber, 0, 8, TaskMonitor.DUMMY);
			if (reader.getLimit() == 0) {
				return null;
			}

			// In support of debug.
			debugReader = reader;
			PdbLog.message(this::debugDump);

			int headerSignature = reader.parseInt();
			int versionNumber = reader.parseInt();

			if (headerSignature == DBIHDR700_SIG) {
				switch (versionNumber) {
					case DBI41_ID:
					case DBI50_ID:
					case DBI60_ID:
					case DBI70_ID:
					case DBI110_ID:
						debugInfo = new PdbNewDebugInfo(pdb, streamNumber);
						break;
					default:
						throw new PdbException("Unknown DBI Version");
				}
			}
			else {
				debugInfo = new PdbOldDebugInfo(pdb, streamNumber);
			}
		}
		catch (CancelledException e) {
			throw new AssertException();
		}
		return debugInfo;
	}

	private String debugDump() {
		return "DebugInfoParser data on stream " + getStreamNumber() + ":\n" +
			debugReader.dump() + "\n";
	}

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Returns the standard stream number that contains the serialized Database Interface.
	 * @return Stream number that contains the Database Interface.
	 */
	protected int getStreamNumber() {
		return DATABASE_INTERFACE_STREAM_NUMBER;
	}

}
