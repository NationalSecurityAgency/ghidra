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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents the the Stream Table used by the Multi-Stream Format File within
 *  Windows PDB files.
 *  We have intended to implement to the Microsoft PDB API (source); see the API for truth.
 */
abstract class AbstractMsfStreamTable {

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected AbstractMsf msf;
	protected List<MsfStream> mapStreamNumberToStream;

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Constructor.
	 * @param msf The {@link AbstractMsf} to which this class is associated.
	 */
	AbstractMsfStreamTable(AbstractMsf msf) {
		this.msf = msf;
		mapStreamNumberToStream = new ArrayList<>();
	}

	/**
	 * Gets the number of streams in the stream table.
	 * @return Number of streams.
	 */
	int getNumStreams() {
		return mapStreamNumberToStream.size();
	}

	/**
	 * Returns the {@link MsfStream} from the stream table indexed by the streamNumber.
	 * @param streamNumber The number ID of the stream to retrieve.
	 * @return {@link MsfStream} or {@code null} if no stream for the streamNumber.
	 */
	MsfStream getStream(int streamNumber) {
		return mapStreamNumberToStream.get(streamNumber);
	}

	/**
	 * Loads Stream Table information from the serial stream contained in the Directory Stream.
	 * @param directoryStream The {@link MsfStream} that contains the serial information to be
	 *  deserialized.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon error with PDB format.
	 * @throws CancelledException Upon user cancellation.
	 */
	void deserialize(MsfStream directoryStream, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		// Read whole stream and then take selections from the byte array, as needed.
		int length = directoryStream.getLength();
		byte[] bytes = directoryStream.read(0, length, monitor);
		PdbByteReader reader = new PdbByteReader(bytes);

		// V2.00 has short followed by an unused short.  We will presume it 0x0000 and process all
		// four bytes into an integer--hopefully not hurting our first short value.
		// This allows the V2.00 and V7.00 to use the same code for getting numStreams.
		int numStreams = reader.parseInt();
		checkMaxStreamsExceeded(numStreams);

		// Get stream lengths and create streams.
		for (int streamNum = 0; streamNum < numStreams; streamNum++) {
			monitor.checkCanceled();
			int streamLength = reader.parseInt();
			parseExtraField(reader);
			MsfStream stream = new MsfStream(msf, streamLength);
			mapStreamNumberToStream.add(stream);
		}

		// Populate the streams with their page information.
		for (int streamNum = 0; streamNum < numStreams; streamNum++) {
			monitor.checkCanceled();
			MsfStream stream = mapStreamNumberToStream.get(streamNum);
			if (stream != null) {
				stream.deserializePageNumbers(reader, monitor);
			}
		}

		// Now replace the directoryStream in the table with the directoryStream taken from the
		//  header, as it is more up-to-date than then entry in the table.
		setStream(msf.getDirectoryStreamNumber(), directoryStream, monitor);
	}

	/**
	 * Put a {@link MsfStream} into the Stream Table at the index location.  If the index location
	 *  does not exist, then enough dummy Streams are added to the table to allow the new
	 *  {@link MsfStream} to be added at the index location.
	 * @param index The location (reference number) for the {@link MsfStream} to be added
	 * (possibly as a replacement).
	 * @param stream The {@link MsfStream} to be added or used to replace an existing Stream.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws CancelledException Upon user cancellation.
	 */
	void setStream(int index, MsfStream stream, TaskMonitor monitor) throws CancelledException {
		if (index < mapStreamNumberToStream.size()) {
			mapStreamNumberToStream.set(index, stream);
		}
		else {
			for (int i = mapStreamNumberToStream.size(); i < index; i++) {
				monitor.checkCanceled();
				mapStreamNumberToStream.add(null);
			}
			mapStreamNumberToStream.add(stream);
		}
	}

	private void checkMaxStreamsExceeded(int numStreams) throws PdbException {
		if (numStreams >= getMaxNumStreamsAllowed()) {
			throw new PdbException(
				String.format("Maximum number of MsfStream exceeded (0X%X >= 0X%X)", numStreams,
					getMaxNumStreamsAllowed()));
		}
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Abstract method to reads/parse extra field for each entry.
	 * @param reader The {@link PdbByteReader} that contains the data/location to parse.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseExtraField(PdbByteReader reader) throws PdbException;

	/**
	 * Returns the maximum number of MsfStreams allowed.
	 * @return The maximum number of MsfStreams allowed.
	 */
	protected abstract int getMaxNumStreamsAllowed();

}
