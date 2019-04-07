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
package ghidra.feature.vt.gui.provider.matchtable;

import java.util.Objects;

/**
 * Checks to see if one number range is a subset of the other
 */
public interface NumberRangeSubFilterChecker {

	/**
	 * Returns true if filter 'a' is a more specific version of filter 'b'
	 * 
	 * @param a the potential sub-filter
	 * @param b the potential parent filter
	 * @return true if filter 'a' is a more specific version of filter 'b'
	 */
	public default boolean isSubFilterOf(NumberRangeProducer a, NumberRangeProducer b) {

		Class<? extends NumberRangeProducer> clazzA = a.getClass();
		Class<? extends NumberRangeProducer> clazzB = b.getClass();
		if (!(clazzA.equals(clazzB))) {
			return false;
		}

		//
		// For a this range to be a sub-filter, this lower bound must be greater than the other
		// filter and this upper bound must be less than the other filter.  In this way, this
		// range is inside of the other range.
		//

		Number lowerA = a.getLowerNumber();
		Number lowerB = b.getLowerNumber();
		if (!isGreaterThanOrEqual(lowerA, lowerB)) {
			return false;
		}

		Number upperA = a.getUpperNumber();
		Number upperB = b.getUpperNumber();
		if (!isLessThanOrEqual(upperA, upperB)) {
			return false;
		}

		return true;
	}

	private boolean isGreaterThanOrEqual(Number a, Number b) {

		if (Objects.equals(a, b)) {
			return true;
		}

		if (a == null || b == null) {
			return false;
		}

		Double doubleA = a.doubleValue();
		Double doubleB = b.doubleValue();
		int result = doubleA.compareTo(doubleB);
		if (result > 0) {
			return true; // a is larger than b
		}

		return false;
	}

	private boolean isLessThanOrEqual(Number a, Number b) {

		if (Objects.equals(a, b)) {
			return true;
		}

		if (a == null || b == null) {
			return false;
		}

		Double doubleA = a.doubleValue();
		Double doubleB = b.doubleValue();
		int result = doubleA.compareTo(doubleB);
		if (result < 0) {
			return true; // a is less than b
		}

		return false;
	}
}
