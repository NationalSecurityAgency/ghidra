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

import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.exception.NoValueException;

/**
*
* This class modifies the behavior of LongIntHashtable. May add
* to the value stored with the key rather than replacing the value.
* 
*/
public class AddableLongIntHashtable extends LongIntHashtable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public AddableLongIntHashtable(int capacity) {
		super(capacity);
	}

	public AddableLongIntHashtable() {
		super();
	}

	/** Adds value associated with the stored key */
	public void add(long key, int value) {

		try {
			if (this.contains(key)) {
				int oldValue = this.get(key);
				int newValue = oldValue + value;
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
