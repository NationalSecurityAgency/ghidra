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
import java.util.concurrent.atomic.AtomicInteger;
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

	private Icon INCOMING_ICON = Icons.ARROW_UP_LEFT_ICON;
	private Icon INCOMING_FUNCTION_ICON;

	private Icon icon = null;
	private final Address functionAddress;
	protected final Program program;
	protected final Function function;
	protected String name;
	protected final boolean filterDuplicates;
	private final Address sourceAddress;

	IncomingCallNode(Program program, Function function, Address sourceAddress,
			boolean filterDuplicates, AtomicInteger filterDepth) {
		super(filterDepth);
		this.program = program;
		this.function = function;
		this.name = function.getName();
		this.sourceAddress = sourceAddress;
		this.filterDuplicates = filterDuplicates;
		this.functionAddress = function.getEntryPoint();

		MultiIcon incomingFunctionIcon = new MultiIcon(INCOMING_ICON, false, 32, 16);
		TranslateIcon translateIcon = new TranslateIcon(CallTreePlugin.FUNCTION_ICON, 16, 0);
		incomingFunctionIcon.addIcon(translateIcon);
		INCOMING_FUNCTION_ICON = incomingFunctionIcon;

		setAllowsDuplicates(!filterDuplicates);
	}

	@Override
	CallNode recreate() {
		return new IncomingCallNode(program, function, sourceAddress, filterDuplicates,
			filterDepth);
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

		FunctionSignatureFieldLocation location =
			new FunctionSignatureFieldLocation(program, functionAddress);

		Set<Address> addresses = ReferenceUtils.getReferenceAddresses(location, monitor);
		LazyMap<Function, List<GTreeNode>> nodesByFunction =
			LazyMap.lazyMap(new HashMap<>(), k -> new ArrayList<>());
		FunctionManager functionManager = program.getFunctionManager();
		for (Address fromAddress : addresses) {
			monitor.checkCanceled();
			Function callerFunction = functionManager.getFunctionContaining(fromAddress);
			if (callerFunction == null) {
				continue;
			}

			IncomingCallNode node = new IncomingCallNode(program, callerFunction, fromAddress,
				filterDuplicates, filterDepth);
			addNode(nodesByFunction, node);
		}

		List<GTreeNode> children =
			nodesByFunction.values()
					.stream()
					.flatMap(list -> list.stream())
					.collect(Collectors.toList());
		Collections.sort(children, new CallNodeComparator());

		return children;
	}

	@Override
	public Address getSourceAddress() {
		return sourceAddress;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (icon == null) {
			icon = INCOMING_FUNCTION_ICON;
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
