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
package ghidra.app.util.bin.format.coff.archive;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A string table that contains the full filenames of COFF archive members who's actual
 * filenames can not fit in the fixed-length name 
 * {@link CoffArchiveMemberHeader#getName() field}.
 * <p>
 * This string table is held in a special archive member named "//" and is usually one of
 * the first members of the archive.
 * <p>
 * With MS libs, this will typically be the 3rd member in the archive, right after 
 * the first and second "/" special members.
 */
public final class LongNamesMember implements StructConverter {

	/**
	 * 
	 * Entries in the long file names string table are terminated either with
	 * \0 (mslib) or \n (linux ar).
	 * MINOR TODO: figure out which kind of archive file this is and use the exact
	 * term char for parsing the string table.
	 */
	private static final String LONGNAME_STR_TERM_CHARS = "\0\n";
	private int _nStrings;
	private long _fileOffset;
	private List<Integer> lengths = new ArrayList<Integer>();

	public LongNamesMember(BinaryReader reader, CoffArchiveMemberHeader header)
			throws IOException {
		this._fileOffset = reader.getPointerIndex();

		long tmpOffset = _fileOffset;
		long endOfStrings = tmpOffset + header.getSize();
		reader.setPointerIndex(endOfStrings);

		while (tmpOffset < endOfStrings) {
			String s = reader.readTerminatedString(tmpOffset, LONGNAME_STR_TERM_CHARS);
			tmpOffset += s.length() + 1;
			++_nStrings;
			lengths.add(s.length() + 1);
		}
	}

	public long getFileOffset() {
		return _fileOffset;
	}

	public String getStringAtOffset(ByteProvider provider, long offset) throws IOException {
		BinaryReader reader = new BinaryReader(provider, false);
		return reader.readTerminatedString(_fileOffset + offset, LONGNAME_STR_TERM_CHARS);
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName(LongNamesMember.class);
		String uniqueName = name + "_" + _nStrings;
		Structure struct = new StructureDataType(uniqueName, 0);
		for (int i = 0 ; i < _nStrings ; ++i) {
			struct.add(STRING, lengths.get(i), "string["+i+"]", null);
		}
		return struct;
	}

	public String findName(ByteProvider provider, CoffArchiveMemberHeader archiveMemberHeader)
			throws IOException {
		String nm = archiveMemberHeader.getName();
		if (nm.startsWith(CoffArchiveMemberHeader.SLASH)) {
			try {
				int offset = Integer.parseInt(nm.substring(1));
				nm = getStringAtOffset(provider, offset);
			}
			catch (NumberFormatException nfe) {
				// ignore
			}
		}
		else if (nm.endsWith(CoffArchiveMemberHeader.SLASH)) {
			nm = nm.substring(0, nm.length() - 1);
		}
		return nm;
	}
}
