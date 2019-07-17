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
package ghidra.util;


/**
 * <code>MultiComparableArrayIterator</code> takes multiple arrays of comparable
 * objects and iterates through them simultaneously. The arrays must contain objects
 * that are comparable within each array and between the multiple arrays.
 * All arrays must be sorted in ascending order when handed to this class. 
 * Iterating returns the next object(s) from one or more of the arrays based on
 * the compareTo() of the next objects in each of the arrays. If a particular
 * array doesn't contain the next object, based on all arrays, then a null is 
 * returned as the next object for that array.
 */
public class MultiComparableArrayIterator<T extends Comparable<T>> {

	T[][] compArrays;
	T[] comps;
	int[] indices;
	boolean forward;

	/**
	 * Constructor of a multi-comparable object array iterator for traversing 
	 * multiple comparable object arrays simultaneously.
	 * <br>Important: The items in each array must be in ascending order.
	 * 
	 * @param arrays the array of Comparable object arrays. 
	 * Each array needs to be in ascending order.
	 */
	public MultiComparableArrayIterator(final T[][] arrays) {
		this(arrays, true);
	}

	/**
	 * Constructor of a multi comparable object array iterator for traversing 
	 * multiple comparable object arrays simultaneously.
	 * 
	 * @param arrays the array of Comparable object arrays.
	 * Each array needs to be in ascending order.
	 * @param forward true indicates that the iterator return comparable objects from min to max.
	 * false indicates to iterate backwards (from max to min).
	 */
	public MultiComparableArrayIterator(final T[][] arrays, boolean forward) {
		this.compArrays = arrays;
		this.forward = forward;
		Class<?> arrayClass = compArrays.getClass().getComponentType().getComponentType();
		this.comps = (T[]) java.lang.reflect.Array.newInstance(arrayClass, compArrays.length);
		this.indices = new int[compArrays.length];
		if (!forward) {
			for (int i = 0; i < compArrays.length; i++) {
				indices[i] = compArrays[i].length - 1;
			}
		}
	}

	/** Determines whether or not any of the original arrays has a
	 *  next object.
	 * @return true if a next object can be obtained from any of
	 * the comparable object arrays.
	 */
	public boolean hasNext() {
		for (int i = 0; i < compArrays.length; i++) {
			if ((indices[i] >= 0) && (compArrays[i].length > indices[i])) {
				return true;
			}
		}
		return false;
	}

	/** Returns the next comparable object(s). The next object could be from any 
	 * one or more of the arrays. The object array returned corresponds to the 
	 * comparable arrays originally passed to the constructor. All objects 
	 * returned are effectively the same as determined by the compareTo() method. 
	 * If the next object for one of the original comparable arrays is not the 
	 * same as the next overall object, then a null is returned in its place.
	 * 
	 * @return an array with the next object found for each of the original arrays.
	 * Some of these may be null, indicating the corresponding comparable array 
	 * didn't possess the next object. However, that comparable array may still 
	 * have objects on subsequent calls.
	 * There will be as many elements in this array as the number of comparable 
	 * arrays passed to the constructor. 
	 */
	public T[] next() {
		T[] nextComps =
			(T[]) java.lang.reflect.Array.newInstance(comps.getClass().getComponentType(),
				comps.length);
		// Get a next value from each variable array
		for (int i = 0; i < compArrays.length; i++) {
			if (comps[i] == null) {
				if ((indices[i] >= 0) && (indices[i] < compArrays[i].length)) {
					comps[i] = compArrays[i][indices[i]];
				}
			}
		}

		// Find next variable.
		T compNext = null;
		boolean next[] = new boolean[comps.length];
//		for (int i = (forward ? 0 : comps.length-1); 
//				(forward ? (i < comps.length) : (i >= 0)); 
//				i=(forward ? i+1 : i-1)) {
		for (int i = 0; i < comps.length; i++) {
			if (comps[i] == null) {
				continue;
			}
			if (compNext == null) {
				compNext = comps[i];
				next[i] = true;
			}
			else {
				int result = compNext.compareTo(comps[i]);
				if (result == 0) {
					next[i] = true;
				}
				else if ((forward && (result > 0)) || (!forward && (result < 0))) {
					compNext = comps[i];
					for (int n = 0; n < i; n++) {
						next[n] = false;
					}
					next[i] = true;
				}
			}
		}

		// Return next comparable object(s) or nulls if none.
		for (int i = 0; i < comps.length; i++) {
			if (next[i]) {
				nextComps[i] = comps[i];
				comps[i] = null;
				if (forward) {
					indices[i]++;
				}
				else {
					indices[i]--;
				}
			}
		}
		return nextComps;
	}

//	public static void main(String[] args) throws InvalidInputException {
//		Variable[] v1 = new Variable[] {
//				new StackLocalVariableImpl("Local_10_v1", null, -0x10, "comment10", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_8_v1", null, -0x8, "comment8.0", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_8_4_v1", null, -0x8, "comment8.4", SourceType.USER_DEFINED)
//		};
//		Variable[] v2 = new Variable[] {
//				new StackLocalVariableImpl("Local_10_v2", null, -0x10, "comment10", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_a_v2", null, -0xa, "commenta", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_8_4_v2", null, -0x8, "comment8.4", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_4_v2", null, -0x4, "comment4.0", SourceType.USER_DEFINED)
//		};
//		Variable[] v3 = new Variable[] {
//				new StackLocalVariableImpl("Local_18_v3", null, -0x18, "comment18", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_14_v3", null, -0x14, "comment14", SourceType.USER_DEFINED)
//		};
//		
//		Arrays.sort(v1);
//		Arrays.sort(v2);
//		Arrays.sort(v3);
//		MultiComparableArrayIterator<Variable> iter = 
//			new MultiComparableArrayIterator<Variable>(
//					new Variable[][] {
//							v1, v2, v3
//							});
//		for (int i=0; iter.hasNext(); i++) {
//			System.out.println(i+": FORWARDS");
//			Variable[] comps = iter.next();
//			Variable[] vars = new Variable[comps.length];
//			System.arraycopy(comps, 0, vars, 0, comps.length);
//			for(int j=0; j<vars.length; j++) {
//				if (vars[j] == null) {
//					System.out.println("   v"+(j+1)+" none");
//				}
//				else {
//					System.out.println("   v"+(j+1)+" "+vars[j].getName()+" "+((StackVariable)vars[j]).getStackOffset()+" "+vars[j].getFirstUseOffset());
//				}
//			}
//		}
//
//		System.out.println(" ");
//		
//		Variable[] b1 = new Variable[] {
//				new StackLocalVariableImpl("Local_8_4_b1", null, -0x8, "comment8.4", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_8_b1", null, -0x8, "comment8.0", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_10_b1", null, -0x10, "comment10", SourceType.USER_DEFINED)
//		};
//		Variable[] b2 = new Variable[] {
//				new StackLocalVariableImpl("Local_4_b2", null, -0x4, "comment4.0", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_8_4_b2", null, -0x8, "comment8.4", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_a_b2", null, -0xa, "commenta", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_10_b2", null, -0x10, "comment10", SourceType.USER_DEFINED)
//		};
//		Variable[] b3 = new Variable[] {
//				new StackLocalVariableImpl("Local_14_b3", null, -0x14, "comment14", SourceType.USER_DEFINED),
//				new StackLocalVariableImpl("Local_18_b3", null, -0x18, "comment18", SourceType.USER_DEFINED)
//		};
//		
//		Arrays.sort(b1);
//		Arrays.sort(b2);
//		Arrays.sort(b3);
//		iter = new MultiComparableArrayIterator<Variable>(new Variable[][] {v1, v2, v3}, false);
//		for (int i=0; iter.hasNext(); i++) {
//			System.out.println(i+": BACKWARDS");
//			Variable[] comps = iter.next();
//			Variable[] vars = new Variable[comps.length];
//			System.arraycopy(comps, 0, vars, 0, comps.length);
//			for(int j=0; j<vars.length; j++) {
//				if (vars[j] == null) {
//					System.out.println("   v"+(j+1)+" none");
//				}
//				else {
//					System.out.println("   v"+(j+1)+" "+vars[j].getName()+" "+((StackVariable)vars[j]).getStackOffset()+" "+vars[j].getFirstUseOffset());
//				}
//			}
//		}
//	}

}
