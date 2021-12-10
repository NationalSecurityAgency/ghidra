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
package ghidra.file.formats.ext4;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

/**
 * Container of parsed Ext4 extended attribute entries
 */
public class Ext4Xattributes {
	/**
	 * Parses extended attributes found at the end of an Inode.
	 * 
	 * @param reader {@link BinaryReader} positioned at the end of the used inode fields
	 * @param endOfInode file position of the end of inode
	 * @return new {@link Ext4Xattributes} instance, or null if not present
	 * @throws IOException if error when reading
	 */
	public static Ext4Xattributes readInodeXAttributes(BinaryReader reader, long endOfInode)
			throws IOException {
		if (reader.getPointerIndex() + Ext4XattrIbodyHeader.SIZEOF >= endOfInode) {
			return null;
		}
		Ext4XattrIbodyHeader eaHeader = new Ext4XattrIbodyHeader(reader);
		if (!eaHeader.isValid()) {
			return null;
		}
		long eaEntriesStart = reader.getPointerIndex();
		List<Ext4XattrEntry> eaEntries = new ArrayList<>();
		while (reader.getPointerIndex() < endOfInode) {
			Ext4XattrEntry eaEntry = new Ext4XattrEntry(reader);
			if (eaEntry.isEndOfListMarker()) {
				break;
			}
			if (!eaEntry.isValid()) {
				Msg.debug(Ext4Xattributes.class, "Bad Ext4XattrEntry: " + reader.getPointerIndex());
				break;
			}
			if (eaEntry.getE_value_offs() > 0 && eaEntry.getE_value_size() > 0) {
				eaEntry.setValue(reader.readByteArray(eaEntriesStart + eaEntry.getE_value_offs(),
					eaEntry.getE_value_size()));
			}
			eaEntries.add(eaEntry);
		}
		return new Ext4Xattributes(eaEntries);
	}

	private List<Ext4XattrEntry> eaEntries;

	private Ext4Xattributes(List<Ext4XattrEntry> eaEntries) {
		this.eaEntries = eaEntries;
	}

	public Ext4XattrEntry getAttribute(String attributeName) {
		for (Ext4XattrEntry eaEntry : eaEntries) {
			if (eaEntry.getName().equals(attributeName)) {
				return eaEntry;
			}
		}
		return null;
	}
}
