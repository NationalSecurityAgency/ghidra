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

		LazyMap<Function, List<GTreeNode>> nodesByFunction =
			LazyMap.lazyMap(new HashMap<>(), k -> new ArrayList<>());
		FunctionManager functionManager = program.getFunctionManager();

		Set<Address> thunkAddrSet = Set.of();
		Function currentFunction = functionManager.getFunctionAt(address);
		if (currentFunction != null) {

			if (currentFunction.isThunk() && !callTreeOptions.allowsThunks()) {
				// If this is a thunk and thunks are filtered-out we must force current function 
				// to the real function
				currentFunction = currentFunction.getThunkedFunction(true);
			}

			// Check to see if current function is thunked
			Address[] functionThunkAddresses =
				currentFunction.getFunctionThunkAddresses(!callTreeOptions.allowsThunks());
			if (functionThunkAddresses != null) {
				thunkAddrSet = Set.of(functionThunkAddresses);
				for (Address thunkAddr : functionThunkAddresses) {
					if (address.equals(thunkAddr)) {
						continue; // avoid possible recursive thunk (should not occur)
					}
					Function thunkFunction = functionManager.getFunctionAt(thunkAddr);
					if (callTreeOptions.allowsThunks()) {
						// include thunk node in tree
						IncomingCallNode node =
							new IncomingCallNode(program, thunkFunction, thunkAddr, true,
								callTreeOptions);
						addNode(nodesByFunction, node);
					}
					else {
						// Do NOT include thunk in tree but follow references to the thunk
						collectIncomingByReference(thunkAddr, nodesByFunction, thunkAddrSet,
							monitor);
					}
				}
			}
		}

		collectIncomingByReference(address, nodesByFunction, thunkAddrSet, monitor);

		List<GTreeNode> children = nodesByFunction.values()
				.stream()
				.flatMap(list -> list.stream())
				.collect(Collectors.toList());
		results.addAll(children);
	}

	private void collectIncomingByReference(Address address,
			LazyMap<Function, List<GTreeNode>> nodesByFunction,
			Set<Address> ignoreFromSet, TaskMonitor monitor)
			throws CancelledException {
		FunctionManager functionManager = program.getFunctionManager();
		ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(address);
		while (refIter.hasNext()) {
			monitor.checkCancelled();
			Reference ref = refIter.next();
			Address fromAddress = ref.getFromAddress();
			Function caller = functionManager.getFunctionContaining(fromAddress);
			if (caller == null) {
				continue;
			}

			if (ignoreFromSet.contains(caller.getEntryPoint())) {
				continue; // ignore references for a thunk relationship (e.g., jump, etc.)
			}

			IncomingCallNode node =
				new IncomingCallNode(program, caller, fromAddress, ref.getReferenceType().isCall(),
					callTreeOptions);
			addNode(nodesByFunction, node);
		}
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
