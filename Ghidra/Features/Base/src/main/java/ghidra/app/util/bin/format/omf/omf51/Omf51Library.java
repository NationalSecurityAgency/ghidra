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
package ghidra.app.util.bin.format.omf.omf51;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.app.util.bin.format.omf.omf.OmfLibraryRecord.MemberHeader;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class Omf51Library {

	private Omf51RecordFactory factory;
	private ArrayList<MemberHeader> members = new ArrayList<>();

	public static class MemberHeader {
		public long offset;
		public long size;
		public String name;
	}
	
	/**
	 * Creates a new {@link Omf51Library}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 */
	public Omf51Library(Omf51RecordFactory factory) {
		this.factory = factory;
	}

	/**
	 * Attempts to parse OMF-51 library members
	 * 
	 * @throws IOException if an IO-related error occurred
	 * @throws OmfException if the required OMF-51 records could not be read
	 */
	public void parseMembers() throws IOException, OmfException {
		OmfRecord record = factory.readNextRecord();

		if (record == null || !(record instanceof Omf51LibraryHeaderRecord)) {
			throw new OmfException("Unable to read library header record");
		}

		Omf51LibraryHeaderRecord libraryHeader = (Omf51LibraryHeaderRecord)record;

		factory.getReader().setPointerIndex(libraryHeader.getModNamesOffset());

		record = factory.readNextRecord();

		if (record == null || !(record instanceof Omf51LibraryModuleNamesRecord)) {
			throw new OmfException("Unable to read library module names record");
		}

		Omf51LibraryModuleNamesRecord modNamesRecord = (Omf51LibraryModuleNamesRecord)record;

		record = factory.readNextRecord();

		if (record == null || !(record instanceof Omf51LibraryModuleLocationsRecord)) {
			throw new OmfException("Unable to read library module locations record");
		}

		Omf51LibraryModuleLocationsRecord modLocations = (Omf51LibraryModuleLocationsRecord)record;
		List<Omf51LibraryModuleLocation> locations = modLocations.getLocations();

		int index = 0;
		Msg.info(this, "Iterating mod names");
		for (OmfString moduleName : modNamesRecord.getNames()) {
			int size = 0;
			if (index + 1 < locations.size()) {
				size = locations.get(index + 1).getOffset() - locations.get(index).getOffset();
			} else {
				size = libraryHeader.getModNamesOffset() - locations.get(index).getOffset();
			}
			
			MemberHeader header = new MemberHeader();
			header.name = moduleName.str();
			header.size = size;
			header.offset = locations.get(index).getOffset();
			
			members.add(header);

			index++;
		}
	}
	
	/**
	 * {@return the list of members}
	 */
	public ArrayList<MemberHeader> getMembers() {
		return members;
	}
}
