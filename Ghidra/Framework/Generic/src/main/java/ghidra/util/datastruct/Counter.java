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
package ghidra.util.datastruct;

import org.apache.commons.lang3.mutable.MutableInt;

/**
 * Simple class used to avoid immutable objects and autoboxing when storing changing integer 
 * primitives in a collection.
 */
public class Counter extends MutableInt {
	/**
	 * Construct a new counter with an initial value of 0.
	 */
	public Counter() {
		super(0);
	}

	/**
	 * Construct a new Counter with the given initial value.
	 * @param value the initial value
	 */
	public Counter(int value) {
		super(value);
	}

	/**
	 * Returns the value of this counter.
	 * @return the value of this counter
	 */
	public int count() {
		return intValue();
	}
}
