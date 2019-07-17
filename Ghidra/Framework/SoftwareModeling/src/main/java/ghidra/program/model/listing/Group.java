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
	 * Returns whether this fragment contains the given code unit.<P>
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
}
