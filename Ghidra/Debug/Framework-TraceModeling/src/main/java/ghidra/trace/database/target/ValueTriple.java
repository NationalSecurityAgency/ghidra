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
package ghidra.trace.database.target;

import java.util.Objects;

import ghidra.util.database.DBCachedObjectStoreFactory.RecAddress;
import ghidra.util.database.spatial.hyper.HyperPoint;

record ValueTriple(long parentKey, long childKey, String entryKey, long snap, RecAddress address)
		implements HyperPoint {
	public ValueTriple(long parentKey, long childKey, String entryKey, long snap,
			RecAddress address) {
		this.parentKey = parentKey;
		this.childKey = childKey;
		this.entryKey = entryKey;
		this.snap = snap;
		this.address = Objects.requireNonNull(address);
	}
}
