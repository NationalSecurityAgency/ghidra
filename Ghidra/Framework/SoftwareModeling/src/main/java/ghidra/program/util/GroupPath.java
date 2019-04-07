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

import ghidra.program.model.listing.*;

import java.io.Serializable;

/**
 * The <CODE>GroupPath</CODE> is a class to represent a unique path in a tree for a Group.
 */
public class GroupPath implements Serializable {
    private final static long serialVersionUID = 1;

	private String []groupNames;

	/**
	 * Construct a new GroupPath that is only a single level.
	 * @param groupName name of group
	 */
    public GroupPath(String groupName) {
		groupNames = new String[1];
		groupNames[0] = groupName;

    }
    
    /**
     * Construct a new GroupPath with the given names.
     * @param groupNames group names. The first name is the oldest ancestor
     * and the last name is the youngest descendant in the path.
     */
    public GroupPath(String[] groupNames) {
		this.groupNames = new String[groupNames.length];
		System.arraycopy(groupNames, 0, this.groupNames, 0,
			groupNames.length);
    }
    
	/**
	 * Update this group path with the new group name wherever the old group name is found.
	 * @param oldname old name
	 * @param newname new name
	 */
    public void updateGroupPath(String oldname, String newname) {
        for(int i=0;i<groupNames.length;i++) {
            if (groupNames[i].equals(oldname)) {
                groupNames[i] = newname;
            }
        }

    }
    
    /**
     * @see java.lang.Object#equals(Object)
     */
    @Override
    public boolean equals(Object obj) {

		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		GroupPath p = (GroupPath)obj;

		if (groupNames.length != p.groupNames.length) {
			return false;
		}
		for (int i=0; i<groupNames.length; i++) {
			if (!groupNames[i].equals(p.groupNames[i])) {
				return false;
			}
		}
		return true;
    }
    
	/**
	 * Get the last name in the path.
	 * @return String
	 */
    public String getLastPathComponent() {
        return groupNames[groupNames.length-1];
    }

	/**
	 * Get the Group for this group path object.
	 * @return null if there is no group with the name in this
	 * group path.
	 */
	public Group getGroup(Program program, String treeName) {
		Listing listing = program.getListing();

		// first try getting a module
		ProgramModule m = listing.getModule(treeName, groupNames[groupNames.length-1]);
		if (m != null) {
			return m;
		}
		// try getting a fragment
		return listing.getFragment(treeName, groupNames[groupNames.length-1]);
	}

	/**
	 * Get the parent path for this group.
	 */
    public GroupPath getParentPath() {
		if (groupNames.length == 1) {
			return null;
		}
		String []p = new String[groupNames.length-1];
		System.arraycopy(groupNames, 0, p, 0, p.length);
		return new GroupPath(p);
    }

	/**
	 * Return the array of names that make up this group's path.
	 */
    public String[] getPath() {
        return groupNames;
    }

	/**
	 * Get the number of names (levels) that make up this path.
	 */
	public int getPathCount() {
        return groupNames.length;
    }

	/**
	 * Get the name at the given index into this group's path.
	 * @param index the index in the group path
	 */
    public String getPathComponent(int index) {
        return groupNames[index];
    }

    /**
     * Return true if the indicated group path is a descendent of this group path.
     * @param grpPath the group path
     */
    public boolean isDescendant(GroupPath grpPath) {
		if (groupNames.length > grpPath.groupNames.length ) {
			return false;
		}
		if (equals(grpPath)) {
			return true;
		}

		for (int i=0; i<groupNames.length; i++) {
			if (!groupNames[i].equals(grpPath.groupNames[i])) {
				return false;
			}
		}
		return true;
    }

	/**
	 * Create a new GroupPath object by adding the given
	 * child name to this group path.
     * 
     * @param child name of child to add to path
	 */
    public GroupPath pathByAddingChild(String child) {
		String []p = new String[groupNames.length+1];
		System.arraycopy(groupNames, 0, p, 0, groupNames.length);
		p[p.length-1] = child;
        return new GroupPath(p);
    }

	/**
	 * Returns a string representation of this group path.
	 */
    @Override
    public String toString() {
		StringBuffer sb = new StringBuffer();
		for (int i=0; i<groupNames.length; i++) {
			sb.append(groupNames[i]);
			if (i < groupNames.length-1) {
				sb.append(", ");
			}
		}
        return sb.toString();
    }
    
    /**
     * @see java.lang.Object#hashCode()
     */
	@Override
    public int hashCode() {
		int hash = 0;
		for(int i=0;i<groupNames.length;i++) {
			hash += groupNames[i].hashCode();
		}
		return hash;
	}
}
