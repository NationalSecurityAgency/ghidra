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
package ghidra.app.plugin.core.register;

import java.awt.Dimension;
import java.awt.Point;
import java.util.*;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import docking.widgets.tree.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import resources.ResourceManager;

public class RegisterTree extends GTree {
	private Program program;
	private RegisterTreeRootNode root;
	private boolean isFiltered;

	public RegisterTree() {
		super(new RegisterTreeRootNode());
		root = (RegisterTreeRootNode) getModelRoot();

		setEditable(false);

		getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		setHorizontalScrollPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

		// add change listener to prevent tree from scrolling horizontally since we will
		// never have a horizontal scroll bar.
		JScrollPane scrollPane = getScrollPane();
		final JViewport viewport = scrollPane.getViewport();
		scrollPane.getViewport().addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				Point viewPosition = viewport.getViewPosition();
				if (viewPosition.x != 0) {
					// if it scrolls horizontally, put it back
					viewPosition.x = 0;
					viewport.setViewPosition(viewPosition);
				}
			}
		});
		setMinimumSize(new Dimension(175, 30));
	}

	void setProgram(Program program) {
		cancelWork();
		this.program = program;
		Register[] registers = null;
		if (program != null) {
			registers =
				isFiltered ? program.getProgramContext().getRegistersWithValues()
						: getNonHiddenRegisters(program);
		}
		else {
			registers = new Register[0];
		}
		root.setRegisters(registers);
	}

	private static Register[] getNonHiddenRegisters(Program program) {
		ArrayList<Register> list = new ArrayList<Register>();
		for (Register reg : program.getProgramContext().getRegisters()) {
			if (!reg.isHidden()) {
				list.add(reg);
			}
		}
		Collections.sort(list);
		Register[] registers = new Register[list.size()];
		return list.toArray(registers);
	}

	void setFiltered(boolean b) {
		isFiltered = b;
		if (program != null) {
			Register[] registers =
				isFiltered ? program.getProgramContext().getRegistersWithValues()
						: getNonHiddenRegisters(program);
			root.setRegisters(registers);
		}
	}

	public void selectRegister(Register register) {
		GTreeNode node = root.findNode(register);
		if (node != null) {
			TreePath path = node.getTreePath();
			setSelectionPath(path);
			scrollPathToVisible(path);
		}
	}

	public void updateFilterList() {
		if (isFiltered) {
			final Register currentRegister = getSelectedRegister();
			Register[] registers = program.getProgramContext().getRegistersWithValues();
			root.setRegisters(registers);
			selectRegister(currentRegister);

// TODO: old school	- delete me?
//			runWhenTreeIsDone(new Runnable() {
//				public void run() {
//					selectRegister(currentRegister);
//				}
//			});
		}
	}

	Register getSelectedRegister() {
		TreePath selectionPath = getSelectionPath();
		if (selectionPath == null) {
			return null;
		}

		Object item = selectionPath.getLastPathComponent();
		if (item instanceof RegisterTreeNode) {
			return ((RegisterTreeNode) item).getRegister();
		}
		return null;
	}
}

abstract class SearchableRegisterTreeNode extends GTreeNode {
	public GTreeNode findNode(Register register) {
		List<GTreeNode> allChildren = getChildren();
		for (GTreeNode child : allChildren) {
			if (!(child instanceof RegisterTreeNode)) {
				continue;
			}
			RegisterTreeNode node = (RegisterTreeNode) child;
			if (node.getRegister().equals(register)) {
				return node;
			}

			GTreeNode foundNode = ((SearchableRegisterTreeNode) child).findNode(register);
			if (foundNode != null) {
				return foundNode;
			}
		}

		return null;
	}
}

class RegisterTreeRootNode extends SearchableRegisterTreeNode {
	private Register[] lastRegisters;

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getName() {
		return "Registers";
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	public void setRegisters(Register[] registers) {
		if (registers == lastRegisters) {
			return;
		}
		removeAll(); // remove all current children before repopulating

		lastRegisters = registers;
		HashMap<String, RegisterTreeGroupNode> groups =
			new HashMap<String, RegisterTreeGroupNode>();

		List<GTreeNode> nodes = new ArrayList<GTreeNode>();

		for (Register register : registers) {
			if (register.getBaseRegister() != register &&
				!register.getParentRegister().isHidden()) {
				continue;
			}
			String groupName = register.getGroup();
			if (groupName != null) {
				RegisterTreeGroupNode group = groups.get(groupName);
				if (group == null) {
					group = new RegisterTreeGroupNode(groupName);
					groups.put(groupName, group);
					nodes.add(group);
				}
				group.addRegister(register);
			}
			else {
				nodes.add(new RegisterTreeNode(register));
			}
		}
		Collections.sort(nodes);
		setChildren(nodes);
	}
}

class RegisterTreeNode extends SearchableRegisterTreeNode {
	private static ImageIcon REG_ICON = ResourceManager.loadImage("images/registerIcon.png");
	private static ImageIcon REG_GROUP_ICON = ResourceManager.loadImage("images/registerGroup.png");
	private final Register register;

	public RegisterTreeNode(Register register) {
		this.register = register;
		for (Register childRegister : register.getChildRegisters()) {
			addNode(new RegisterTreeNode(childRegister));
		}
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return register.hasChildren() ? REG_GROUP_ICON : REG_ICON;
	}

	@Override
	public String getName() {
		return register.getName() + "  (" + register.getBitLength() + getAliases() + ")";
	}

	private String getAliases() {
		StringBuffer buf = new StringBuffer();
		for (String alias : register.getAliases()) {
			buf.append(buf.length() == 0 ? "; " : ", ");
			buf.append(alias);
		}
		return buf.toString();
	}

	@Override
	public String getToolTip() {
		return register.getDescription();
	}

	@Override
	public boolean isLeaf() {
		return !register.hasChildren();
	}

	@Override
	public int compareTo(GTreeNode other) {
		if (!(other instanceof RegisterTreeNode)) {
			return 1;
		}
		return getName().compareTo(other.getName());
	}

	public Register getRegister() {
		return register;
	}
}

class RegisterTreeGroupNode extends SearchableRegisterTreeNode {
	private static ImageIcon OPEN_ICON = ResourceManager.loadImage("images/openSmallFolder.png");
	private static ImageIcon CLOSED_ICON =
		ResourceManager.loadImage("images/closedSmallFolder.png");
	private String name;

	public RegisterTreeGroupNode(String name) {
		this.name = name;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_ICON : CLOSED_ICON;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	public void addRegister(Register register) {
		addNode(new RegisterTreeNode(register));
	}

	@Override
	public int compareTo(GTreeNode o) {
		if (!(o instanceof RegisterTreeGroupNode)) {
			return -1;
		}
		return name.compareTo(o.getName());
	}
}
