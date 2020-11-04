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
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

public class ExternalCallNode extends CallNode {

	private static final Icon EXTERNAL_ICON = ResourceManager.loadImage("images/package.png");
	private final Icon EXTERNAL_FUNCTION_ICON;
	private final Icon baseIcon;

	private final Function function;
	private final Address sourceAddress;
	private final String name;

	ExternalCallNode(Function function, Address sourceAddress, Icon baseIcon) {
		super(new AtomicInteger(0));  // can't recurse
		this.function = function;
		this.sourceAddress = sourceAddress;
		this.name = function.getName();
		this.baseIcon = baseIcon;

		MultiIcon outgoingFunctionIcon = new MultiIcon(EXTERNAL_ICON, false, 32, 16);
		TranslateIcon translateIcon = new TranslateIcon(baseIcon, 16, 0);
		outgoingFunctionIcon.addIcon(translateIcon);
		EXTERNAL_FUNCTION_ICON = outgoingFunctionIcon;
	}

	@Override
	CallNode recreate() {
		return new ExternalCallNode(function, sourceAddress, baseIcon);
	}

	@Override
	public Function getRemoteFunction() {
		return function;
	}

	@Override
	public ProgramLocation getLocation() {
		return new FunctionSignatureFieldLocation(function.getProgram(), function.getEntryPoint());
	}

	@Override
	public Address getSourceAddress() {
		return sourceAddress;
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		return new ArrayList<GTreeNode>();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return EXTERNAL_FUNCTION_ICON;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getToolTip() {
		return "External Call - called from " + sourceAddress;
	}

	@Override
	public boolean isLeaf() {
		return true;
	}
}
