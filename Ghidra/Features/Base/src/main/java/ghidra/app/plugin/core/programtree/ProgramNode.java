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
package ghidra.app.plugin.core.programtree;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;

import ghidra.program.model.listing.*;
import ghidra.program.util.GroupPath;
import ghidra.util.SystemUtilities;

/**
 * Class to define a node in a DragNDropTree.
 */
public class ProgramNode extends DefaultMutableTreeNode {

	private boolean visited; // true if this node was visited
	transient private Group group; // node representing a Module or Fragment
	transient private ProgramModule module; // null if this node represents a Fragment
	transient private ProgramFragment fragment; // null if this node represents a  Module
	transient private ProgramModule parentModule;
	transient private Program program;
	transient private Listing listing;

	private TreePath path;
	private String name;
	private boolean deleted; // true if this node is marked as deleted
	private GroupPath groupPath;
	private boolean isInView;
	transient private ProgramDnDTree tree; // set only for the root node

	/**
	 * Construct a new ProgramNode with the given Group.
	 */
	ProgramNode(Program program, Group g) {
		this(program, g, g.getName());
	}

	/**
	 * Construct a new ProgramNode with the given name.
	 */
	ProgramNode(Program program, String name) {
		this(program, null, name);
	}

	/**
	 * Create a new ProgramNode with the given group and name;
	 * use name for the displayed name of this node.
	 */
	ProgramNode(Program program, Group g, String name) {
		super(name);
		this.program = program;
		group = g;
		this.name = name;
		if (program != null) {
			listing = program.getListing();
		}
		if (listing != null) {

			if (group instanceof ProgramModule) {
				module = (ProgramModule) group;
			}
			else {
				fragment = (ProgramFragment) group;
				setAllowsChildren(false);
			}
		}
	}

	/** 
	 * Returns true if this node has no children.
	 */
	@Override
	public boolean isLeaf() {
		if (module == null) {
			return true;
		}

		return module.getNumChildren() == 0;
	}

	/**
	 * Returns true if this node is allowed to have children.
	 */
	@Override
	public boolean getAllowsChildren() {
		if (module != null) {
			return true;
		}
		return false;
	}

	/**
	 * Returns whether some other object is "equal to" this one.
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

		ProgramNode other = (ProgramNode) obj;
		if (!SystemUtilities.isEqual(parentModule, other.parentModule)) {
			return false;
		}

		// Note: 'group' is a DB object--there can be only one
		return SystemUtilities.isEqual(group, other.group);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((group == null) ? 0 : group.hashCode());
		result = prime * result + ((parentModule == null) ? 0 : parentModule.hashCode());
		return result;
	}

	public JTree getTree() {
		if (isRoot()) {
			return tree;
		}
		ProgramNode root = (ProgramNode) getRoot();
		return root.getTree();
	}

	/**
	 * Get the name for this node.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the group for this node.
	 */
	public Group getGroup() {
		return group;
	}

	/**
	 * Returns true if this node represents a Fragment.
	 */
	public boolean isFragment() {
		return fragment != null;
	}

	/**
	* Returns true if this node represents a Module.
	 */
	public boolean isModule() {
		return module != null;
	}

	/**
	 * Returns the module if this node represents a Module.
	 * @return null if this node does not represent a Module.
	 */
	public ProgramModule getModule() {
		return module;
	}

	/**
	 * Returns the fragment if this node represents a Fragment.
	 * @return null if this node does not represent a Fragment.
	 */
	public ProgramFragment getFragment() {
		return fragment;
	}

	/**
	 * Get the program for this node.
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Return true if the node is in the view.
	 */
	public boolean isInView() {
		return isInView;
	}

	/**
	 * Get the group path for this node.
	 */
	public GroupPath getGroupPath() {
		return groupPath;
	}

	/////////////////////////////////////////////////////////////
	// package-level methods
	/////////////////////////////////////////////////////////////
	/**
	 * Mark this node as having been populated (visited).
	 */
	void visit() {
		if (visited || module == null) {
			return;
		}

		visited = true;
	}

	/**
	 * Return true if this node was visited.
	 */
	boolean wasVisited() {
		return visited;
	}

	void setGroup(Group g) {
		group = g;
	}

	/**
	 * Get the tree path for this node.
	 */
	TreePath getTreePath() {
		return path;
	}

	/**
	 * Set the tree path for this node.
	 */
	void setTreePath(TreePath path) {
		this.path = path;
	}

	/**
	 * Get the parent module for this node.
	 */
	ProgramModule getParentModule() {
		return parentModule;
	}

	/**
	 * Set the parent module for this node.
	 */
	void setParentModule(ProgramModule parent) {
		parentModule = parent;
	}

	/**
	 * Set the name for this node.
	 */
	void setName(String name) {
		this.name = name;
		super.setUserObject(name);
	}

	/**
	 * Set this node to be deleted so that it can be
	 * rendered as such.
	 */
	void setDeleted(boolean deleted) {
		this.deleted = deleted;
	}

	/**
	 * Returns whether this node is marked as deleted.
	 */
	boolean isDeleted() {
		return deleted;
	}

	/**
	 * Set the group path for this node.
	 */
	void setGroupPath(GroupPath groupPath) {
		this.groupPath = groupPath;
	}

	/**
	 * Mark this node as being in some view.
	 */
	void setInView(boolean isInView) {
		this.isInView = isInView;
	}

	/**
	 * Recursively check if any descendants of this node is in the view.
	 * 
	 * @return boolean true if any descendants of this node is in the view
	 */
	boolean hasDescendantsInView() {
		if (isInView) {
			return true;
		}
		for (int i = 0; i < getChildCount(); i++) {
			ProgramNode child = (ProgramNode) getChildAt(i);
			if (child.isInView()) {
				return true;
			}
			if (child.getAllowsChildren()) {
				if (child.hasDescendantsInView()) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Set the tree; this method is only called on the root node.
	 */
	void setTree(ProgramDnDTree tree) {
		this.tree = tree;
	}

	/**
	 * Clear fields so this object can be garbage collected.
	 */
	void dispose() {
		program = null;
		listing = null;
		module = null;
		fragment = null;
		group = null;
		parentModule = null;
		path = null;
		groupPath = null;
	}

	boolean isValid(Object versionTag) {
		if (group == null) {
			return true;
		}

		if (module != null) {
			return versionTag == module.getVersionTag();
		}
		return true;
	}

	/**
	 * Get the node named childName.
	 * @param childName
	 * @return null if the node does not allow children, or the name was
	 * not found.
	 */
	ProgramNode getChild(String childName) {
		if (getAllowsChildren()) {
			int nchild = getChildCount();
			for (int i = 0; i < nchild; i++) {
				ProgramNode c = (ProgramNode) getChildAt(i);
				if (c.getName().equals(childName)) {
					return c;
				}
			}
		}
		return null;
	}
}
