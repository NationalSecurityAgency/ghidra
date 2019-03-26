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
package ghidra.util.table;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;


class IntObjectCache {
	private MySoftRef[] values;
	private ReferenceQueue<Object> refQueue;
	
	IntObjectCache(int size) {
		try {
			values = new MySoftRef[size];
			refQueue = new ReferenceQueue<Object>();
		} catch(Throwable t) {
		}
	}
	
	void put(int index, Object obj) {
		if (values != null) {
			removeStaleEntries();
			values[index] = new MySoftRef(index, obj, refQueue);
		}
	}
	Object get(int index) {
		if (values != null) {
			removeStaleEntries();
			if (values[index] != null) {
				return values[index].get();
			}
		}
		return null;
	}
	
	/**
     * Expunge stale entries from the table.
     */
    private void removeStaleEntries() {
        Object r;
        while ( (r = refQueue.poll()) != null) {
        	MySoftRef e = (MySoftRef)r;
        	values[e.index] = null;
        }
    }

	private static class MySoftRef extends SoftReference<Object> {
		int index;
		MySoftRef(int index, Object obj, ReferenceQueue<Object> refQueue) {
			super(obj, refQueue);
			this.index = index;
		}
	}
}
