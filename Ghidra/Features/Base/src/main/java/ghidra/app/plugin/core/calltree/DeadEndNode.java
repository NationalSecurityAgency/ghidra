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
package ghidra.app.plugin.core.calltree;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DeadEndNode extends CallNode {

	private static final Icon DEAD_END_ICON = new GIcon("icon.plugin.calltree.node.dead.end");
	private static final Icon CALL_REFERENCE_ICON = createIcon(DEAD_END_ICON, true);
	private static final Icon NON_CALL_REFERENCE_ICON = createIcon(DEAD_END_ICON, false);

	private final Reference reference;
	private String name;

	private final Program program;

	DeadEndNode(Program program, Reference reference, CallTreeOptions callTreeOptions) {
		super(callTreeOptions);
		this.program = program;
		this.reference = reference;
		this.isCallReference = reference.getReferenceType().isCall();
	}

	@Override
	public int loadAll(TaskMonitor monitor) throws CancelledException {
		return 1; // this node cannot be opened
	}

	@Override
	CallNode recreate() {
		return new DeadEndNode(program, reference, callTreeOptions);
	}

	@Override
	public Function getRemoteFunction() {
		return null; // no function--dead end
	}

	@Override
	public Address getSourceAddress() {
		return reference.getFromAddress();
	}

	public Address getRemoteAddress() {
		return reference.getToAddress();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return isCallReference ? CALL_REFERENCE_ICON : NON_CALL_REFERENCE_ICON;
	}

	@Override
	public String getName() {
		if (name == null) {
			Address toAddress = reference.getToAddress();
			SymbolTable symbolTable = program.getSymbolTable();
			Symbol symbol = symbolTable.getPrimarySymbol(toAddress);
			if (symbol != null) {
				name = symbol.getName();
			}
			else {
				name = toAddress.toString();
			}
		}
		return name;
	}

	@Override
	public boolean isLeaf() {
		return true;
	}

	@Override
	public ProgramLocation getLocation() {
		return new ProgramLocation(program, reference.getToAddress());
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		return new ArrayList<>();
	}
}
