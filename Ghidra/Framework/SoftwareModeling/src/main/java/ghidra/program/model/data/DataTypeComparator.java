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
 * {@link DataTypeComparator} provides the preferred named-based comparison of {@link DataType}
 * which utilizes the {@link DataTypeNameComparator} for a primary {@link DataType#getName() name} 
 * comparison followed by sub-ordering on {@link DataTypeManager} name and {@link CategoryPath}.
 */
public class DataTypeComparator implements Comparator<DataType> {

	public static DataTypeComparator INSTANCE = new DataTypeComparator();

	@Override
	public int compare(DataType dt1, DataType dt2) {
		String name1 = dt1.getName();
		String name2 = dt2.getName();

		int nameCompare = DataTypeNameComparator.INSTANCE.compare(name1, name2);
		if (nameCompare == 0) {

			DataTypeManager dtm1 = dt1.getDataTypeManager();
			String dtmName1 = dtm1 != null ? dtm1.getName() : null;

			DataTypeManager dtm2 = dt2.getDataTypeManager();
			String dtmName2 = dtm2 != null ? dtm2.getName() : null;

			if (dtm1 == null) {
				if (dtm2 != null) {
					return -1;
				}
			}
			if (dtm2 == null) {
				return 1;
			}

			// Compare DataTypeManager names if datatypes have the same name
			int compare = dtmName1.compareTo(dtmName2);
			if (compare == 0) {

				// Compare category paths if they have the same name and DTM
				String catPath1 = dt1.getCategoryPath().getPath();
				String catPath2 = dt2.getCategoryPath().getPath();
				compare = catPath1.compareTo(catPath2);
			}
			return compare;
		}
		return nameCompare;
	}
}
