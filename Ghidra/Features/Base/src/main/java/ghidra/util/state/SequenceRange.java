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
package ghidra.util.state;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.SequenceNumber;

public class SequenceRange {

	private final SequenceNumber start;
	private final SequenceNumber end;

	public SequenceRange(SequenceNumber start, SequenceNumber end) {
		this.start = start;
		this.end = end;
	}

	public SequenceNumber getStart() {
		return start;
	}

	public SequenceNumber getEnd() {
		return end;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof SequenceRange)) {
			return false;
		}
		SequenceRange range = (SequenceRange)obj;
		return start.equals(range.start) && end.equals(range.end);
	}

	@Override
	public int hashCode() {
		return start.hashCode();
	}

	@Override
	public String toString() {
		return start + "-" + end;
	}
	
	public boolean contains(SequenceNumber seq) {
		Address addr = seq.getTarget();
		int index = seq.getTime();
		Address startAddr = start.getTarget();
		int startIndex = start.getTime();
		Address endAddr = end.getTarget();
		int endIndex = end.getTime();
		int c = addr.compareTo(startAddr);
		if (c == 0) {
			c = index - startIndex;
		}
		if (c < 0) {
			return false;
		}
		c = addr.compareTo(endAddr);
		if (c == 0) {
			c = index - endIndex;
		}
		return c <= 0;
	}
	
	
	
}
