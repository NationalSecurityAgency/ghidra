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

public class DataTypeComparator implements Comparator<Object> {

	@Override
	public int compare(Object o1, Object o2) {

		if (o1 instanceof DataType && o2 instanceof DataType) {
			DataType dt1 = (DataType) o1;
			DataType dt2 = (DataType) o2;

			String name1 = dt1.getName();
			String name2 = dt2.getName();

			// if the names are the same, then sort by the path            
			int nameResult = name1.compareToIgnoreCase(name2);
			if (nameResult != 0) {
				return nameResult;
			}

			String dtmName1 = dt1.getDataTypeManager().getName();
			String dtmName2 = dt2.getDataTypeManager().getName();

			// if they have the same name, and are in the same DTM, then compare paths
			int dtmResult = dtmName1.compareToIgnoreCase(dtmName2);
			if (dtmResult != 0) {
				return dtmResult;
			}

			return dt1.getPathName().compareToIgnoreCase(dt2.getPathName());
		}
		// these cases are for lookups by string keys        
		else if (o1 instanceof String && o2 instanceof DataType) {

			DataType dt2 = (DataType) o2;
			String name2 = dt2.getName();

			return ((String) o1).compareToIgnoreCase(name2);
		}
		else if (o1 instanceof DataType && o2 instanceof String) {
			DataType dt1 = (DataType) o1;
			String name1 = dt1.getName();

			return name1.compareToIgnoreCase(((String) o2));
		}

		return 0;
	}
}
