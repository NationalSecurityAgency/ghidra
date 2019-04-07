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
package ghidra.program.model.address;

import java.util.Comparator;

/**
 * Compares an address against an AddressRange.
 * <P>
 */
public class AddressRangeToAddressComparator implements Comparator<Object> {
	/**
	 * Compares an address against an AddressRange.
	 * @param obj1 the first object to compare. Must be an address or an address range.
	 * @param obj2 the second object to compare. Must be an address or an address range.
	 * <P>
     * @return a negative integer, zero, or a positive integer
     *  if the first argument is less than, equal to, or greater than the second.
	 */
    public int compare(Object obj1, Object obj2) {
        if(obj1 instanceof AddressRange) {
            return ((AddressRange) obj1).compareTo((Address) obj2);
        }
        return -((AddressRange) obj2).compareTo((Address) obj1);
    }

}
