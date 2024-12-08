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
package ghidra.program.model.data;

import java.util.Comparator;

/**
 * {@link DataTypeObjectComparator} provides the preferred named-based comparison of data types
 * using the {@link DataTypeNameComparator} allowing a mix of {@link DataType} and/or {@link String}
 * names to be compared. 
 */
public class DataTypeObjectComparator implements Comparator<Object> {

	public static DataTypeObjectComparator INSTANCE = new DataTypeObjectComparator();

	/**
	 * Compare two data type names
	 * @param o1 the first {@link DataType} or {@link String} name to be compared.
	 * @param o2 the second {@link DataType} or {@link String} name to be compared.
	 * @return a negative integer, zero, or a positive integer as the
	 *         first argument is less than, equal to, or greater than the
	 *         second.
	 * @throws IllegalArgumentException if object types other than {@link DataType} or 
	 * {@link String} are compared.
	 */
	@Override
	public int compare(Object o1, Object o2) {

		String name1, name2;
		if (o1 instanceof DataType && o2 instanceof DataType) {
			DataType dt1 = (DataType) o1;
			name1 = dt1.getName();
			DataType dt2 = (DataType) o2;
			name2 = dt2.getName();
		}
		// these cases are for lookups by string keys        
		else if (o1 instanceof String && o2 instanceof DataType) {
			name1 = (String) o1;
			DataType dt2 = (DataType) o2;
			name2 = dt2.getName();
		}
		else if (o1 instanceof DataType && o2 instanceof String) {
			DataType dt1 = (DataType) o1;
			name1 = dt1.getName();
			name2 = (String) o2;
		}
		else if (o1 instanceof String && o2 instanceof String) {
			name1 = (String) o1;
			name2 = (String) o2;
		}
		else {
			throw new IllegalArgumentException("Unsupported comparison " +
				o1.getClass().getSimpleName() + " / " + o2.getClass().getSimpleName());
		}
		return DataTypeNameComparator.INSTANCE.compare(name1, name2);
	}
}
