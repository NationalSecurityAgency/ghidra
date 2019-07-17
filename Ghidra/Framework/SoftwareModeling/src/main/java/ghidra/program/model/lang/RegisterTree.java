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
package ghidra.program.model.lang;

import java.util.ArrayList;
import java.util.List;

/**
 * The RegisterTree class builds and represents relationships between registers. Any
 * register that "breaks down" into smaller registers can be represent by a 
 * RegisterTree.  The largest register will be at the root and the registers that
 * make it up will be its children trees.  The children are RegisterTrees as well
 * and can have children trees of thier own.  The root of a RegisterTree may not
 * have an associated Register which means that its children are unrelated.  This
 * way all the registers of a processor can be represented as a single RegisterTree.
 */
public class RegisterTree implements Comparable<RegisterTree> {
	private static final String SEPARATOR = ".";
	private Register register;
	private RegisterTree parent;
	private ArrayList<RegisterTree> children;
	private String name;

	public RegisterTree(Register reg) {
		this.name = reg.getName();
		this.register = reg;
		List<Register> registerChildren = reg.getChildRegisters();
		this.children = new ArrayList<RegisterTree>();
		for (Register childReg : registerChildren) {
			RegisterTree tree = new RegisterTree(childReg);
			tree.parent = this;
			this.children.add(tree);
		}
	}

	/**
	 * Constructs a RegisterTree with the given name and set of registers
	 * @param name the name of the tree
	 * @param regs the array of registers to form into a tree
	 */
	public RegisterTree(String name, Register[] regs) {
		this.name = name;
		children = new ArrayList<RegisterTree>();
		for (Register reg : regs) {
			if (reg.isBaseRegister()) {
				RegisterTree tree = new RegisterTree(reg);
				tree.parent = this;
				children.add(tree);
			}
		}
	}

	/**
	 * Constructs a RegisterTree with one RegisterTree child
	 * @param name the name of this tree
	 * @param tree the child tree.
	 */
	public RegisterTree(String name, RegisterTree tree) {
		this.name = name;
		children = new ArrayList<RegisterTree>();
		children.add(tree);
	}

	/**
	 * Returns the name of this register tree.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Adds a Register Tree to this tree.
	 * @param tree the register tree to add
	 */
	public void add(RegisterTree tree) {
		children.add(tree);
		tree.parent = this;
	}

	/**
	 * Get the RegisterTrees that are the children of this RegisterTree
	 * @return a array of RegisterTrees
	 */
	public RegisterTree[] getComponents() {
		return children.toArray(new RegisterTree[children.size()]);
	}

	/**
	 * Returns the Register associated with this tree. This may be null which
	 * indicates the children RegisterTrees are unrelated to each other.
	 */
	public Register getRegister() {
		return register;
	}

	/**
	 * Returns the parent RegisterTree.
	 */
	public RegisterTree getParent() {
		return parent;
	}

	/**
	 * The parent path of this RegisterTree if it exists or null if this tree has no parent or
	 * no parent with a register.
	 * @return The parent path of this RegisterTree.
	 */
	public String getParentRegisterPath() {
		RegisterTree parentTree = getParent();
		if (parentTree == null || (parentTree.getRegister() == null)) {
			return null;
		}

		return parentTree.getRegisterPath();
	}

	/**
	 * The path of this register, which includes the parent path of this RegisterTree if this
	 * RegisterTree has a parent.
	 * @return the path of this register.
	 */
	public String getRegisterPath() {
		String parentPath = getParentRegisterPath();

		if (parentPath != null) {
			return parentPath + SEPARATOR + getRegister().getName();
		}

		return getRegister().getName();
	}

	/**
	 * Returns the RegisterTree for the given register if one exists in this RegisterTree object.
	 * @param  register1 The register for which to get a RegisterTree.
	 * @return The RegisterTree for the given register if one exists in this RegisterTree object.
	 */
	public RegisterTree getRegisterTree(Register register1) {
		if (this.register == register1) {
			return this;
		}
		for (RegisterTree child : children) {
			RegisterTree tree = child.getRegisterTree(register1);
			if (tree != null) {
				return tree;
			}
		}
		return null;
	}

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	public int compareTo(RegisterTree other) {
		return name.compareTo(other.name);
	}

	/**
	 * Removes the register from the children
	 * @param reg the register to remove.
	 */
	public void remove(Register reg) {
		RegisterTree tree = getRegisterTree(reg);
		if (tree == null) {
			return;
		}
		if (tree.getParent() == null) {
			return;
		}
		tree.getParent().children.remove(tree);
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer(name);
		buffer.append('[');
		for (RegisterTree child : children) {
			buffer.append(child.toString());
			buffer.append(',');
		}
		buffer.append(']');
		return buffer.toString();
	}
}
