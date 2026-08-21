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

import ghidra.app.util.bin.format.omf.OmfException;
import ghidra.app.util.bin.format.omf.OmfString;

public class Omf51Library {

	private List<MemberHeader> members = new ArrayList<>();

	public record MemberHeader(long offset, long size, String name) {}

	/**
	 * Creates a new {@link Omf51Library}
	 * 
	 * @param factory A {@link Omf51RecordFactory}
	 * @throws IOException if an IO-related error occurred
	 * @throws OmfException if the required OMF-51 records could not be read
	 */
	public Omf51Library(Omf51RecordFactory factory) throws OmfException, IOException {
		if (!(factory.readNextRecord() instanceof Omf51LibraryHeaderRecord libraryHeader)) {
			throw new OmfException("Unable to read library header record");
		}

		factory.getReader().setPointerIndex(libraryHeader.getModNamesOffset());

		if (!(factory.readNextRecord() instanceof Omf51LibraryModuleNamesRecord modNamesRecord)) {
			throw new OmfException("Unable to read library module names record");
		}

		if (!(factory.readNextRecord() instanceof Omf51LibraryModuleLocationsRecord modLocations)) {
			throw new OmfException("Unable to read library module locations record");
		}

		List<Omf51LibraryModuleLocation> locations = modLocations.getLocations();

		int index = 0;
		for (OmfString moduleName : modNamesRecord.getNames()) {
			int currentOffset = locations.get(index).getOffset();
			int nextOffset = index + 1 < locations.size() ? locations.get(index + 1).getOffset()
					: libraryHeader.getModNamesOffset();
			int size = nextOffset - currentOffset;
			members.add(new MemberHeader(currentOffset, size, moduleName.str()));
			index++;
		}
	}

	/**
	 * {@return the list of members}
	 */
	public List<MemberHeader> getMembers() {
		return members;
	}
}
