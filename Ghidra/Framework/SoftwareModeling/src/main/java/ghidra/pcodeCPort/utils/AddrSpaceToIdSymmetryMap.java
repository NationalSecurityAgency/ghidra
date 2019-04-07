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
package ghidra.pcodeCPort.utils;

import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.util.datastruct.WeakValueHashMap;

public class AddrSpaceToIdSymmetryMap {
	private AddrSpaceToIdSymmetryMap() {
	}

	private static long idGenerator = 10000; // use a high start number to avoid collisions

	private static WeakValueHashMap<Long, AddrSpace> idToSpaceMap = new WeakValueHashMap<>();
	private static WeakValueHashMap<AddrSpace, Long> spaceToIdMap = new WeakValueHashMap<>();

	public static synchronized long getID(AddrSpace space) {
		Long id = spaceToIdMap.get(space);
		if (id == null) {
			id = idGenerator++;
			idToSpaceMap.put(id, space);
		}

		return id;
	}

	public static synchronized AddrSpace getSpace(long ID) {
		return idToSpaceMap.get(ID);
	}
}
