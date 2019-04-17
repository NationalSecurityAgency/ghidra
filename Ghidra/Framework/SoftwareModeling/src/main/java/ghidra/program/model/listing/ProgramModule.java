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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.*;

/**
 * A <CODE>ProgramModule</CODE> is a group of <CODE>ProgramFragment</CODE>s 
 * and/or other <CODE>ProgramModule</CODE>s together with some related 
 * information such as a name, comment, and alias. Users create modules to 
 * overlay the program with a hierarchical structure. A <I>child</I> of a module 
 * is a fragment or module which it directly contains. A <I>parent</I> of a module 
 * is a module which has this module as a child. A module may be contained in more 
 * than one module. A <CODE>Program</CODE> always has at least one module, the root module. 
 * The root module cannot be removed and is the ancestor for all other modules and
 * fragments in the program.
 */
public interface ProgramModule extends Group {

	/**
	 * Returns whether this module directly contains the
	 * given fragment as a child.
	 * 
	 * @param fragment the fragment to check.
	 */
    public boolean contains(ProgramFragment fragment);
	
	/**
	 * Returns whether this module directly contains the
	 * given module as a child.
	 *
	 * @param module the module to check.
     * @return true if module is the same as this module, or if module
     * is a child of this module.
	 */
    public boolean contains(ProgramModule module);
	
	/**
	 * Returns the number of children of this module.
	 */
    public int getNumChildren();
	
	/**
	 * Returns an array containing this module's children.
	 */
    public Group[] getChildren();
		  
	/**
	 * Get the index of the child with the given name.
	 * @param name name of child
	 * @return int index or -1 if this Module does not have a child
	 * with the given name
	 */
	public int getIndex(String name);  
	/**
	 * Adds the given module as a child of this module.
	 * <P>
	 * @param module the module to be added.
	 * @throws CircularDependencyException thrown if the module being
	 * added is an ancestor of this module. The module structure of
	 * a program does not allow "cycles" of this sort to be created.
	 * @exception DuplicateGroupException thrown if the module being
	 * added is already a child of this module.
	 */
    public void add(ProgramModule module)
		throws CircularDependencyException, DuplicateGroupException;
	
	/**
	 * Adds the given fragment as a child of this module.
	 * <P>
	 * @exception DuplicateGroupException thrown if the fragment being
	 * added is already a child of this module.	 
	 */
    public void add(ProgramFragment fragment)
        throws DuplicateGroupException;
	
	/**
	 * Creates a new module and makes it a child of this
	 * module.<P>
	 *
	 * @param moduleName the name to use for the new module.
	 * 
	 * @return the newly created module.
	 * @exception DuplicateNameException thrown if the given
	 * name is already used by an existing module or fragment.
	 */
    public ProgramModule createModule(String moduleName)throws DuplicateNameException;
	
	/**
	 * Creates a new fragment and makes it a child of this module.<P>
	 * 
	 * @param fragmentName the name to use for the new fragment.
	 * 
	 * @return the newly created fragment.
	 * @exception DuplicateNameException thrown if the given
	 * name is already used by an existing module or fragment.
	 */
    public ProgramFragment createFragment(String fragmentName) throws DuplicateNameException;
	
    /**
     * Reparents child with the given name to this Module; removes the
     * child from oldParent.
     * @param name name of child to reparent
     * @param oldParent old parent
     * @exception NotFoundException if name is not the name of a child
     * in oldParent
     */
    public void reparent(String name, ProgramModule oldParent) 
        throws NotFoundException;

	/**
	 * Changes the ordering of this module's children by moving
	 * the child with the given name to position given by index.<P>
	 *
	 * @param name the name of the child to move.
	 * @param index the index to move it to.
	 * @exception NotFoundException thrown if a child with the given
	 * name cannot be found in this module.
	 */
    public void moveChild(String name, int index) throws NotFoundException;

    /**
     * Removes a child module or fragment from this Module.
     * @return true if successful, false if no child in this module has the given name.
     * @exception NotEmptyException thrown if the module appears in no other
     * modules and it is not empty.
     */
    public boolean removeChild(String name) throws NotEmptyException;    	
			
	/**
	 * Returns whether the given module is a descendant of this
	 * module.<P>
	 * @param module the module to check.
	 * 
	 * @return true if the module is a descendant, false otherwise.
	 */
	public boolean isDescendant(ProgramModule module);

	/**
	 * Returns whether the given fragment is a descendant of this
	 * module.<P>
	 * @param fragment the fragment to check.
	 * 
	 * @return true if the fragment is a descendant, false otherwise.
	 */
	public boolean isDescendant(ProgramFragment fragment);

	/**
	 * Returns the minimum address of this module which will be the minimum
	 * address from the set of all fragments which are descendants of this
	 * module.
	 * <P>
	 * @return the minimum address, this will be null if all of the module's
	 * descendant fragments are empty.
	 */
	public Address getMinAddress();

	/**
	 * Returns the maximum address of this module which will be the maximum
	 * address from the set of all fragments which are descendants of this
	 * module.
	 * <P>
	 * @return the maximum address, this will be null if all of the module's
	 * descendant fragments are empty.
	 */
	public Address getMaxAddress();

	/**
	 * Returns the first address of this module which will be the minimum
	 * address of the first descendant fragment which is non-empty. In other
	 * words this returns the first address for this module as defined by
	 * the user ordering of the module's children.
	 * <P>
	 * @return the first address, this will be null if all of the module's
	 * descendant fragments are empty.
	 */
	public Address getFirstAddress();

	/**
	 * Returns the last address of this module which will be the maximum address
	 * of the last descendant fragment which is non-empty. In other words this
	 * returns the last address for this module as defined by the user
	 * ordering of the module's children.
	 * <P>
	 * @return the last address, this will be null if all of the module's
	 * descendant fragments are empty.
	 */
	public Address getLastAddress();
	
	/**
	 * Returns the set of addresses for this module which will be the combined 
	 * set of addresses from the set of all fragments which are descendants of this
	 * module.
	 * @return the complete address set for this module.
	 */
	public AddressSetView getAddressSet();
	
	/**
	 * Returns an object that can be used to detect when the module tree has been affected
	 * by an undo or redo. After an undo/redo, if this module was affected, then a new
	 * verionTag object is created.
	 */
	public Object getVersionTag();
	
	/**
	 * Get the current modification number of the module tree; the number 
	 * is updated when ever a change is made to any module or fragment
	 * that is part of this module's root tree. 
	 */
	public long getModificationNumber();
	
	/**
	 * Get the ID for the tree that this module belongs to.
	 * @return ID for the tree
	 */
	public long getTreeID();

}
