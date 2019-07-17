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
package ghidra.app.plugin.core.datamgr.util;

import ghidra.program.model.data.DataType;

import java.util.Comparator;

public class DataTypeComparator implements Comparator<DataType> {

    public int compare(DataType dt1, DataType dt2) {
        String name1 = dt1.getName();
        String name2 = dt2.getName();

// TODO: should built-ins always come first in the list? (in case we have an 'a' named archive?)        
        
        // if the names are the same, then sort by the path            
        if ( name1.equalsIgnoreCase( name2 ) ) {

            if ( !name1.equals( name2 ) ) {
                // let equivalent names be sorted by case ('-' for lower-case first)
                return -name1.compareTo( name2 );
            }
            
            String dtmName1 = dt1.getDataTypeManager().getName();
            String dtmName2 = dt2.getDataTypeManager().getName();

            // if they have the same name, and are in the same DTM, then compare paths
            if ( dtmName1.equalsIgnoreCase( dtmName2 ) ) {
                return dt1.getPathName().compareToIgnoreCase( dt2.getPathName() );
            }

            return dtmName1.compareToIgnoreCase( dtmName2 );
        }

        return name1.compareToIgnoreCase( name2 );
    }
}
