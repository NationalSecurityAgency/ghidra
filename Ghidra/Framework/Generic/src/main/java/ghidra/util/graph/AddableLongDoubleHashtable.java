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
package ghidra.util.graph;

import ghidra.util.datastruct.LongDoubleHashtable;
import ghidra.util.exception.NoValueException;

/**
*
* This class modifies the behavior of LongDoubleHashtable. May add
* to the value stored with the key rather than replacing the value.
* 
*/
public class AddableLongDoubleHashtable extends LongDoubleHashtable {
	public AddableLongDoubleHashtable() {
		super();
	}

	/** Constructor creates a table with an initial given capacity.  The capacity
	 * will be adjusted to the next highest prime in the PRIMES table.
	 */
	public AddableLongDoubleHashtable(int capacity) {
		super(capacity);
	}

	/** Adds the value to the stored value rather than replacing it. */
	public void add(long key, double value) {

		try {
			if (this.contains(key)) {
				double oldValue = this.get(key);
				double newValue = oldValue + value;
				this.put(key, newValue);
			}
			else {
				this.put(key, value);
			}
		}
		catch (NoValueException e) {
			//can't happen do nothing
		}
	}

}
