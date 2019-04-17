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
package ghidra.util.datastruct;

import ghidra.util.LongIterator;
import ghidra.util.prop.PropertySet;

/**
 * Iterator over Property Set Index ranges that have the same value
 */
public class PropertySetIndexRangeIterator implements IndexRangeIterator {
	LongIterator longIt;
	IndexRange indexRange;
    /**
     * Constructor for PropertySetIndexRangeIterator.
     */
    public PropertySetIndexRangeIterator(PropertySet set, long start) {
    	longIt = set.getPropertyIterator(start+1);

		if (longIt.hasNext()) {
			indexRange = new IndexRange(start, longIt.next()-1);
		}
		else {
			indexRange = new IndexRange(start, Long.MAX_VALUE);
		}
    }

    /**
     * @see ghidra.util.datastruct.IndexRangeIterator#hasNext()
     */
    public boolean hasNext() {
        return indexRange != null;
    }

    /**
     * @see ghidra.util.datastruct.IndexRangeIterator#next()
     */
    public IndexRange next() {
    	IndexRange temp = indexRange;
    	getNextIndexRange();
    	return temp;
    }

	private void getNextIndexRange() {
		if (indexRange == null) {
			return;
		}
		long oldEnd = indexRange.getEnd();
		if (oldEnd == Long.MAX_VALUE) {
			indexRange = null;
			return;
		}
		if (longIt.hasNext()) {
			indexRange = new IndexRange(oldEnd+1, longIt.next()-1);
			return;
		}
		indexRange = new IndexRange(oldEnd+1, Long.MAX_VALUE);
		
	}
}
