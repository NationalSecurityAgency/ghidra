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
package ghidra.util.ascii;

import ghidra.program.model.data.AbstractStringDataType;

public class Sequence {

	private long start;
	private long end;
	private boolean nullTerminated;
	private AbstractStringDataType stringDataType;

	public Sequence(long start, long end, AbstractStringDataType stringDataType,
			boolean nullTerminated) {
		this.start = start;
		this.end = end;
		this.stringDataType = stringDataType;
		this.nullTerminated = nullTerminated;
	}

	public long getStart() {
		return start;
	}

	public long getEnd() {
		return end;
	}

	public boolean isNullTerminated() {
		return nullTerminated;
	}

	public AbstractStringDataType getStringDataType() {
		return stringDataType;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != getClass()) {
			return false;
		}
		Sequence other = (Sequence) obj;
		return start == other.start && end == other.end && nullTerminated == other.nullTerminated &&
			stringDataType.getClass() == other.stringDataType.getClass();
	}

	@Override
	public int hashCode() {
		return (int) (start + end);
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append('(');
		buf.append(start);
		buf.append(',');
		buf.append(end);
		buf.append(',');
		buf.append(stringDataType.getDisplayName());
		buf.append(',');
		buf.append(nullTerminated);
		buf.append(')');
		return buf.toString();
	}

	public int getLength() {
		return (int) (end - start + 1);
	}
}
