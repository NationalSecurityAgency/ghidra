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
package ghidra.program.util;

import java.util.Collection;

import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Program;

/** 
 * Compares the function tags in two programs. 
 * 
 * Two sets of tags are considered equal if they contain the name and comment
 * attributes.
 * 
 */
class FunctionTagComparator extends ProgramDiff.ProgramDiffComparatorImpl {

	/** 
	 * Generic constructor for comparing program differences.
	 * 
	 * @param program1 the first program
	 * @param program2 the second program
	 */
	FunctionTagComparator(Program program1, Program program2) {
		super(program1, program2);
	}

	/** Compares two function tag lists to determine whether the first 
	 *  tag address is effectively less than (comes before it in memory), 
	 *  equal to (at the same spot in memory), or greater than (comes after 
	 *  it in memory) the second comment's address.
	 *  
	 * @param obj1 the address for the first program's tag.
	 * @param obj2 the address for the second program's tag.
	 * @return -1 if the first comes before the second in memory. 
	 *          0 if the objects are at the same spot in memory.
	 *          1 if the first comes after the second in memory.
	 */
	@Override
	public int compare(Object o1, Object o2) {
		FunctionDB f1 = (FunctionDB) o1;
		FunctionDB f2 = (FunctionDB) o2;

		Address a1 = f1.getEntryPoint();
		Address a2 = f2.getEntryPoint();

		Address address2CompatibleWith1 =
			SimpleDiffUtility.getCompatibleAddress(program2, a2, program1);
		return a1.compareTo(address2CompatibleWith1);
	}

	/** 
	 * Returns whether the tag lists for the given functions contain 
	 * the same items; order is unimportant.
	 * 
	 * @param obj1 the first {@link FunctionDB} object
	 * @param obj2 the second {@link FunctionDB} object
	 * @return true if the tags lists contain the same elements.
	 */
	@Override
	public boolean isSame(Object obj1, Object obj2) {
		FunctionDB f1 = (FunctionDB) obj1;
		FunctionDB f2 = (FunctionDB) obj2;

		if (f1 == null && f2 == null) {
			// Both null - neither is a function so just return true
			return true;
		}
		if (f1 == null || f2 == null) {
			// Someone is not a function, return false
			return false;
		}

		// Get the tag lists and check if they're the same.
		Collection<FunctionTag> f1Tags = f1.getTags();
		Collection<FunctionTag> f2Tags = f2.getTags();
		return f1Tags.equals(f2Tags);
	}

	/** 
	 * Returns the address set that contains the address for the tags.
	 * 
	 * @param obj the object being examined by this comparator.
	 * @param program the program the object is associated with.
	 * @return address set containing the tag location.
	 */
	@Override
	public AddressSet getAddressSet(Object obj, Program program) {
		AddressSet addrs = new AddressSet();
		if (obj == null) {
			return addrs;
		}

		FunctionDB function = (FunctionDB) obj;
		addrs.add(function.getEntryPoint());
		return addrs;
	}
}
