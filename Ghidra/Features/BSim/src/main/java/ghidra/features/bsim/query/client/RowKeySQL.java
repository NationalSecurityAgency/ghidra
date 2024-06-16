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
package ghidra.features.bsim.query.client;

import ghidra.features.bsim.query.description.RowKey;

public class RowKeySQL extends RowKey {
	private long id;			// Unique row id for the record

	public RowKeySQL(long i) {
		id = i;
	}

	@Override
	public int compareTo(RowKey obj) {
		RowKeySQL o = (RowKeySQL)obj;
		return Long.compare(id, o.id);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;
		RowKeySQL o = (RowKeySQL)obj;
		return id == o.id;
	}

	@Override
	public int hashCode() {
		return Long.hashCode(id);
	}

	@Override
	public long getLong() {
		return id;
	}
}
