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
package ghidra.app.util.bin.format.pe.rich;

import ghidra.app.util.bin.format.pe.RichTable;

/**
 * An element of a {@link RichTable}
 */
public class RichHeaderRecord {

	private final int recordIndex;
	private final CompId compid;
	private final int count;

	public RichHeaderRecord(int recordIndex, int compid, int count) {
		this.recordIndex = recordIndex;
		this.compid = new CompId(compid);
		this.count = count;
	}

	public int getIndex() {
		return recordIndex;
	}

	public CompId getCompId() {
		return this.compid;
	}

	public int getObjectCount() {
		return count;
	}

	@Override
	public String toString() {
		return compid + " Count: " + count;
	}
}
