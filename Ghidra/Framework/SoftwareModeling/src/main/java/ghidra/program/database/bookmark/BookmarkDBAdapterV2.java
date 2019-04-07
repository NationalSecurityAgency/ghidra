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
package ghidra.program.database.bookmark;

import ghidra.program.database.map.AddressMap;
import ghidra.util.exception.VersionException;
import db.DBHandle;

/**
 * 
 */
class BookmarkDBAdapterV2 extends BookmarkDBAdapterV1 {

	static final int V2_VERSION = 2;

	/**
	 * Constructor (Version 2 Schema)
	 * 
	 */
	public BookmarkDBAdapterV2(DBHandle dbHandle, AddressMap addrMap) throws VersionException {
		this.addrMap = addrMap.getOldAddressMap();
		table = dbHandle.getTable(BOOKMARK_TABLE_NAME);
		if (table == null) {
			throw new VersionException(true);
		}
		int ver = table.getSchema().getVersion();
		if (ver != V2_VERSION) {
			throw new VersionException(ver < V2_VERSION);
		}
	}
}
