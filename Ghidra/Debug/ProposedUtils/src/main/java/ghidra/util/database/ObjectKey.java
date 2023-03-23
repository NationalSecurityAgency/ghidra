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
package ghidra.util.database;

import java.util.Objects;

import db.Table;

/**
 * An opaque handle uniquely identifying a database-backed object
 */
public class ObjectKey implements Comparable<ObjectKey> {

	private final Table table;
	private final long key;

	private final int hash;

	public ObjectKey(Table table, long key) {
		this.table = table;
		this.key = key;
		this.hash = Objects.hash(System.identityHashCode(table), key);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ObjectKey)) {
			return false;
		}
		ObjectKey that = (ObjectKey) obj;
		if (this.table != that.table) {
			return false;
		}
		if (this.key != that.key) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public int compareTo(ObjectKey that) {
		int result;
		if (this.table != that.table) {
			return System.identityHashCode(this.table) - System.identityHashCode(that.table);
		}
		result = Long.compareUnsigned(this.key, that.key);
		if (result != 0) {
			return result;
		}
		return 0;
	}
}
