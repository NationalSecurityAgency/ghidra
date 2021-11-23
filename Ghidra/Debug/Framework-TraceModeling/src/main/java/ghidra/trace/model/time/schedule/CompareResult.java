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
package ghidra.trace.model.time.schedule;

/**
 * The result of a rich comparison of two schedules (or parts thereof)
 */
public enum CompareResult {
	UNREL_LT(-1, false),
	REL_LT(-1, true),
	EQUALS(0, true),
	REL_GT(1, true),
	UNREL_GT(1, false);

	/**
	 * Enrich the result of {@link Comparable#compareTo(Object)}, given that the two are related
	 * 
	 * @param compareTo the return from {@code compareTo}
	 * @return the rich result
	 */
	public static CompareResult related(int compareTo) {
		if (compareTo < 0) {
			return REL_LT;
		}
		if (compareTo > 0) {
			return REL_GT;
		}
		return EQUALS;
	}

	/**
	 * Enrich the result of {@link Comparable#compareTo(Object)}, given that the two are not
	 * related
	 * 
	 * @param compareTo the return from {@code compareTo}
	 * @return the rich result
	 */
	public static CompareResult unrelated(int compareTo) {
		if (compareTo < 0) {
			return UNREL_LT;
		}
		if (compareTo > 0) {
			return UNREL_GT;
		}
		return EQUALS;
	}

	/**
	 * Maintain sort order, but specify the two are not in fact related
	 * 
	 * @param result the result of another (usually recursive) rich comparison
	 * @return the modified result
	 */
	public static CompareResult unrelated(CompareResult result) {
		return unrelated(result.compareTo);
	}

	public final int compareTo;
	public final boolean related;

	CompareResult(int compareTo, boolean related) {
		this.compareTo = compareTo;
		this.related = related;
	}
}
