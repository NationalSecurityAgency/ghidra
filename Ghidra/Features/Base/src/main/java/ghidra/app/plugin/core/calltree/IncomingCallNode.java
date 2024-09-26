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

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.Icon;

import org.apache.commons.collections4.map.LazyMap;

import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import resources.MultiIcon;
import resources.icons.TranslateIcon;

public class IncomingCallNode extends CallNode {

	private static final Icon INCOMING_ICON = Icons.ARROW_UP_LEFT_ICON;
	private Icon incomingFunctionIcon;

	private Icon icon = null;
	private final Address functionAddress;
	protected final Program program;
	protected final Function function;
	protected String name;
	private final Address sourceAddress;

	IncomingCallNode(Program program, Function function, Address sourceAddress,
			CallTreeOptions callTreeOptions) {
		super(callTreeOptions);
		this.program = program;
		this.function = function;
		this.name = function.getName(callTreeOptions.showNamespace());
		this.sourceAddress = sourceAddress;
		this.functionAddress = function.getEntryPoint();

		MultiIcon multiIcon = new MultiIcon(INCOMING_ICON, false, 32, 16);
		TranslateIcon translateIcon = new TranslateIcon(CallTreePlugin.FUNCTION_ICON, 16, 0);
		multiIcon.addIcon(translateIcon);
		incomingFunctionIcon = multiIcon;
	}

	@Override
	CallNode recreate() {
		return new IncomingCallNode(program, function, sourceAddress, callTreeOptions);
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
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {

		List<GTreeNode> children = new ArrayList<>();
		doGenerateChildren(functionAddress, children, monitor);

		Collections.sort(children, new CallNodeComparator());

		return children;
	}

	private void doGenerateChildren(Address address, List<GTreeNode> results, TaskMonitor monitor)
			throws CancelledException {

		FunctionSignatureFieldLocation location =
			new FunctionSignatureFieldLocation(program, address);

		Set<Address> addresses = ReferenceUtils.getReferenceAddresses(location, monitor);
		LazyMap<Function, List<GTreeNode>> nodesByFunction =
			LazyMap.lazyMap(new HashMap<>(), k -> new ArrayList<>());
		FunctionManager functionManager = program.getFunctionManager();
		for (Address fromAddress : addresses) {
			monitor.checkCancelled();
			Function callerFunction = functionManager.getFunctionContaining(fromAddress);
			if (callerFunction == null) {
				continue;
			}

			// If we are not showing thunks, then replace each thunk with all calls to that thunk
			if (callerFunction.isThunk() && !callTreeOptions.allowsThunks()) {
				Address callerEntry = callerFunction.getEntryPoint();
				doGenerateChildren(callerEntry, results, monitor);
				continue;
			}

			IncomingCallNode node =
				new IncomingCallNode(program, callerFunction, fromAddress, callTreeOptions);
			addNode(nodesByFunction, node);
		}

		List<GTreeNode> children = nodesByFunction.values()
				.stream()
				.flatMap(list -> list.stream())
				.collect(Collectors.toList());
		results.addAll(children);
	}

	@Override
	public Address getSourceAddress() {
		return sourceAddress;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (icon == null) {
			icon = incomingFunctionIcon;
			if (functionIsInPath()) {
				icon = CallTreePlugin.RECURSIVE_ICON;
			}
		}
		return icon;
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
}
