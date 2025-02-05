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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

public class IncomingCallNode extends CallNode {

	private static final Icon INCOMING_ICON = Icons.ARROW_UP_LEFT_ICON;
	private static final Icon CALL_REFERENCE_ICON = createIcon(INCOMING_ICON, true);
	private static final Icon NON_CALL_REFERENCE_ICON = createIcon(INCOMING_ICON, false);
	private static final Icon RECURSIVE_CALL_REFERENCE_ICON = createIcon(RECURSIVE_ICON, true);
	private static final Icon RECURSIVE_NON_CALL_REFERENCE_ICON = createIcon(RECURSIVE_ICON, false);

	private Icon icon = null;
	private final Address functionAddress;
	protected final Program program;
	protected final Function function;
	protected String name;
	private final Address sourceAddress;

	IncomingCallNode(Program program, Function function, Address sourceAddress,
			boolean isCallReference, CallTreeOptions callTreeOptions) {
		super(callTreeOptions);
		this.program = program;
		this.function = function;
		this.name = function.getName(callTreeOptions.showNamespace());
		this.sourceAddress = sourceAddress;
		this.functionAddress = function.getEntryPoint();
		this.isCallReference = isCallReference;
	}

	@Override
	CallNode recreate() {
		return new IncomingCallNode(program, function, sourceAddress, isCallReference,
			callTreeOptions);
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

		ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(address);
		LazyMap<Function, List<GTreeNode>> nodesByFunction =
			LazyMap.lazyMap(new HashMap<>(), k -> new ArrayList<>());
		FunctionManager functionManager = program.getFunctionManager();
		while (refIter.hasNext()) {
			monitor.checkCancelled();
			Reference ref = refIter.next();
			Address fromAddress = ref.getFromAddress();
			Function caller = functionManager.getFunctionContaining(fromAddress);
			if (caller == null) {
				continue;
			}

			// If we are not showing thunks, then replace each thunk with all calls to that thunk
			if (caller.isThunk() && !callTreeOptions.allowsThunks()) {
				Address callerEntry = caller.getEntryPoint();
				if (!address.equals(callerEntry)) { // recursive reference from thunk to itself
					doGenerateChildren(callerEntry, results, monitor);
				}
				continue;
			}

			IncomingCallNode node =
				new IncomingCallNode(program, caller, fromAddress, ref.getReferenceType().isCall(),
					callTreeOptions);
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
			if (functionIsInPath()) {
				icon = isCallReference ? RECURSIVE_CALL_REFERENCE_ICON
						: RECURSIVE_NON_CALL_REFERENCE_ICON;
			}
			else {
				icon = isCallReference ? CALL_REFERENCE_ICON : NON_CALL_REFERENCE_ICON;
			}
		}
		return icon;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}
}
