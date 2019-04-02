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
package ghidra.pdb.pdbreader;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;

/**
 * This class represents Segment Map Description component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public class SegmentMapDescription {

	//==============================================================================================
	// Internals
	//==============================================================================================
	private int flags;
	private int ovl;
	private int group;
	private int frame;
	private int segNameIndex;
	private int classNameIndex;
	private long segOffset;
	private long segLength;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Deserializes the SegmentMapDescription.
	 * @param substreamReader {@link PdbByteReader} from which to deserialize the data.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	void deserialize(PdbByteReader substreamReader) throws PdbException {
		flags = substreamReader.parseUnsignedShortVal();
		ovl = substreamReader.parseUnsignedShortVal();
		group = substreamReader.parseUnsignedShortVal();
		frame = substreamReader.parseUnsignedShortVal();
		segNameIndex = substreamReader.parseUnsignedShortVal();
		classNameIndex = substreamReader.parseUnsignedShortVal();
		segOffset = substreamReader.parseUnsignedIntVal();
		segLength = substreamReader.parseUnsignedIntVal();
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Dumps the SegmentMapDescription.  This method is for debugging only.
	 * @return {@link String} of pretty output.
	 */
	protected String dump() {
		StringBuilder builder = new StringBuilder();
		builder.append("SegmentMapDescription---------------------------------------");
		builder.append("\nflags: ");
		builder.append(flags);
		builder.append("\novl: ");
		builder.append(ovl);
		builder.append("\ngroup: ");
		builder.append(group);
		builder.append("\nframe: ");
		builder.append(frame);
		builder.append("\nsegNameIndex: ");
		builder.append(segNameIndex);
		builder.append("; classNameIndex: ");
		builder.append(classNameIndex);
		builder.append("; segOffset: ");
		builder.append(segOffset);
		builder.append("; segLength: ");
		builder.append(segLength);
		return builder.toString();
	}

}
