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

import ghidra.framework.data.DomainObjectAdapterDB;

/**
 * Enough information to uniquely identify a trace object
 */
public class ObjectKey implements Comparable<ObjectKey> {

	private final DomainObjectAdapterDB adapter;
	private final String tableName;
	private final long key;

	private final int hash;

	public ObjectKey(DomainObjectAdapterDB adapter, String tableName, long key) {
		this.adapter = adapter;
		this.tableName = tableName;
		this.key = key;
		this.hash = Objects.hash(System.identityHashCode(adapter), tableName, key);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ObjectKey)) {
			return false;
		}
		ObjectKey that = (ObjectKey) obj;
		if (this.adapter != that.adapter) {
			return false;
		}
		if (!(Objects.equals(this.tableName, that.tableName))) {
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
		if (this.adapter != that.adapter) {
			result = this.adapter.getName().compareTo(that.adapter.getName());
			if (result != 0) {
				return result;
			}
			return System.identityHashCode(this.adapter) - System.identityHashCode(that.adapter);
		}
		result = this.tableName.compareTo(that.tableName);
		if (result != 0) {
			return result;
		}
		result = Long.compareUnsigned(this.key, that.key);
		if (result != 0) {
			return result;
		}
		return 0;
	}
}
