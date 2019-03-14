/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.macos.asd;

import ghidra.util.Msg;

import java.lang.reflect.Field;

public final class EntryDescriptorID {

	/** The data fork. */
	public final static int ENTRY_DATA_FORK        = 0x1;
	/** The resource fork. */
	public final static int ENTRY_RESOURCE_FORK    = 0x2;
	/** File's name as created on home file system. */
	public final static int ENTRY_REAL_NAME        = 0x3;
	/** Standard Macintosh comment. */
	public final static int ENTRY_COMMENT          = 0x4;
	/** Standard Macintosh black-and-white icon. */
	public final static int ENTRY_ICON_BW          = 0x5;
	/** Macintosh color icon. */
	public final static int ENTRY_ICON_COLOR       = 0x6;
	/** File creation date, modification date, etc. */
	public final static int ENTRY_FILE_DATE_INFO   = 0x7;
	/** Standard Macintosh Finder information. */
	public final static int ENTRY_FINDER_INFO      = 0x8;
	/** Macintosh file information, attributes, etc. */
	public final static int ENTRY_MAC_FILE_INFO    = 0x9;
	/** ProDOS file information, attributes, etc. */
	public final static int ENTRY_PRODOS_FILE_INFO = 0xa;
	/** MS-DOS file information, attributes, etc. */
	public final static int ENTRY_MSDOS_FILE_INFO  = 0xb;
	/** AFP short name. */
	public final static int ENTRY_SHORT_NAME       = 0xc;
	/** AFP file information, attributes, etc. */
	public final static int ENTRY_AFP_FILE_INFO    = 0xd;
	/** AFP directory ID. */
	public final static int ENTRY_DIRECTORY_ID     = 0xe;

	public final static String convertEntryIdToName(int entryID) {
		Field [] fields = EntryDescriptorID.class.getDeclaredFields();
		for (Field field : fields) {
			if (field.getName().startsWith("ENTRY_")) {
				try {
					Integer value = (Integer)field.get(null);
					if (value == entryID) {
						return field.getName().substring("ENTRY_".length());
					}
				}
				catch (Exception e) {
				    Msg.error(EntryDescriptorID.class, "Unexpected Exception: " + e.getMessage(), e);
				}
			}
		}
		return "Unrecognized entry id: 0x"+Integer.toHexString(entryID);
	}
}
