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
package ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.util.GroupPath;
import ghidra.util.exception.DuplicateNameException;

/**
 * The interface for groupings of code units that may have attributes such
 * as names and comments.
 */
public interface Group {
	/**
	 * Obtains the comment that has been associated with this fragment or module.
	 * 
	 * @return may be null.
	 */
	public String getComment();

	/**
	 * Sets the comment to associate with this fragment.
	 * 
	 * @param comment the comment.
	 */
	public void setComment(String comment);

	/**
	 * Obtains the name that has been associated with this fragment. A fragment will
	 * always have a name and it will be unique within the set of all fragment and
	 * module names.
	 */
	public String getName();

	/**
	 * Sets the name of this fragment.
	 * 
	 * @param name   the string to use for the fragment's name.
	 * 
	 * @exception DuplicateNameException
	 *                   thrown if the name being set is already in use by another fragment or a
	 *                   module.
	 */
	public void setName(String name) throws DuplicateNameException;

	/**
	 * Returns whether this fragment contains the given code unit.
	 * 
	 * @param codeUnit the code unit being tested.
	 * 
	 * @return true if the code unit is in the fragment, false otherwise.
	 */
	public boolean contains(CodeUnit codeUnit);

	/**
	 * Obtains the number of parent's of this fragment. If a fragment is in a module
	 * then the module is a <I>parent</I> of the fragment and the fragment is a
	 * <I>child</I> of the module. A fragment must have at least one parent and it
	 * may have multiple parents.
	 * 
	 * @return the number of parents of this fragment.
	 */
	public int getNumParents();

	/**
	 * Returns a list of the modules which are parents for this group.
	 */
	public ProgramModule[] getParents();

	/**
	 * Returns the names of the modules which are parents to this
	 * fragment.
	 */
	public String[] getParentNames();

	/**
	 * Returns the name of the tree that this group belongs to.
	 */
	public String getTreeName();

	/**
	 * Returns true if this group has been deleted from the program
	 * @return true if this group has been deleted from the program
	 */
	public boolean isDeleted();

	public Address getMinAddress();

	public Address getMaxAddress();

	/**
	 * Returns one of many possible GroupPaths for this group. Since Fragments can belong in
	 * more than one module, there can be multiple legitimate group paths for a group. This method
	 * arbitrarily returns one valid group path.
	 * @return one of several possible group paths for this group
	 */
	public default GroupPath getGroupPath() {
		List<String> parentNames = getParentNames(this);
		return new GroupPath(parentNames.toArray(new String[parentNames.size()]));
	}

	private static List<String> getParentNames(Group group) {
		Group[] parents = group.getParents();
		if (parents == null || parents.length == 0) {
			List<String> list = new ArrayList<>();
			list.add(group.getName());
			return list;
		}
		Group parent = parents[0];
		List<String> names = getParentNames(parent);
		names.add(group.getName());
		return names;
	}
}
