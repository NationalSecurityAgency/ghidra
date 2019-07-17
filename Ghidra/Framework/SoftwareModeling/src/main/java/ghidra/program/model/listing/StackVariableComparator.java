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
package ghidra.program.model.listing;

import java.util.Comparator;

/**
 * Compares stack variable offsets; has a static factory method to get
 * a StackVariableComparator.
 * 
 */
public class StackVariableComparator implements Comparator<Object> {
	private static StackVariableComparator acomp = null;

	/**
	 * Compares a stack variable offsets. One or both objects must be
	 * a StackVariable.
	 * @param obj1 a StackVariable or Integer
	 * @param obj2 a StackVariable or Integer
	 * <P>
	 * @return a negative integer, zero, or a positive integer
	 *  if the first argument is less than, equal to, or greater than the second.
	 */
	@Override
	public int compare(Object obj1, Object obj2) {

		Integer offset1 = getStackOffset(obj1, "obj1");
		Integer offset2 = getStackOffset(obj2, "obj2");

		if (offset1 == null) {
			if (offset2 == null) {
				return 0;
			}
			return 1;
		}
		if (offset2 == null) {
			return -1;
		}
		if (offset1 < offset2) {
			return -1;
		}
		if (offset2 < offset1) {
			return 1;
		}
		return 0;
	}

	private Integer getStackOffset(Object obj, String name) {
		if (obj instanceof Variable) {
			Variable var = (Variable) obj;
			if (var.hasStackStorage()) {
				return (int) var.getLastStorageVarnode().getAddress().getOffset();
			}
			return null;
		}
		else if (obj instanceof Integer) {
			return (Integer) obj;
		}
		else {
			throw new IllegalArgumentException(name + " is unsupported type: " +
				obj.getClass().getSimpleName());
		}
	}

	/**
	 * Returns a shared instance of a StackVariableComparator.
	 */
	public static StackVariableComparator get() {
		if (acomp == null) {
			acomp = new StackVariableComparator();
		}
		return (acomp);
	}
}
