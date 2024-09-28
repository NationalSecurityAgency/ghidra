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
import javax.swing.tree.TreePath;

import org.apache.commons.collections4.map.LazyMap;

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import resources.MultiIcon;
import resources.icons.TranslateIcon;

public class OutgoingCallNode extends CallNode {

	private static final Icon OUTGOING_ICON = Icons.ARROW_DOWN_RIGHT_ICON;
	private final Icon outgoingFunctionIcon;

	private Icon icon = null;
	protected final Program program;
	protected final Function function;
	protected String name;
	private final Address sourceAddress;

	OutgoingCallNode(Program program, Function function, Address sourceAddress,
			CallTreeOptions callTreeOptions) {
		super(callTreeOptions);
		this.program = program;
		this.function = function;
		this.name = function.getName(callTreeOptions.showNamespace());
		this.sourceAddress = sourceAddress;

		MultiIcon multiIcon = new MultiIcon(OUTGOING_ICON, false, 32, 16);
		TranslateIcon translateIcon = new TranslateIcon(CallTreePlugin.FUNCTION_ICON, 16, 0);
		multiIcon.addIcon(translateIcon);
		outgoingFunctionIcon = multiIcon;
	}

	@Override
	CallNode recreate() {
		return new OutgoingCallNode(program, function, sourceAddress, callTreeOptions);
	}

	@Override
	public Function getRemoteFunction() {
		return function;
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {

		List<GTreeNode> children = new ArrayList<>();
		Address calledEntry = function.getEntryPoint();
		doGenerateChildren(calledEntry, children, monitor);

		Collections.sort(children, new CallNodeComparator());

		return children;
	}

	private void doGenerateChildren(Address address, List<GTreeNode> results, TaskMonitor monitor)
			throws CancelledException {

		FunctionManager fm = program.getFunctionManager();
		Function currentFunction = fm.getFunctionContaining(address);
		AddressSetView functionBody = currentFunction.getBody();
		Address entryPoint = currentFunction.getEntryPoint();
		Set<Reference> references = getReferencesFrom(program, functionBody, monitor);
		LazyMap<Function, List<GTreeNode>> nodesByFunction =
			LazyMap.lazyMap(new HashMap<>(), k -> new ArrayList<>());
		FunctionManager functionManager = program.getFunctionManager();
		for (Reference reference : references) {
			monitor.checkCancelled();
			Address toAddress = reference.getToAddress();
			if (toAddress.equals(entryPoint)) {
				continue; // recursive
			}

			Function calledFunction = functionManager.getFunctionAt(toAddress);
			if (calledFunction == null) {
				createNode(nodesByFunction, reference, calledFunction);
				continue;
			}

			// If we are not showing thunks, then replace the thunk with the thunked function
			if (calledFunction.isThunk() && !callTreeOptions.allowsThunks()) {
				Function thunkedFunction = calledFunction.getThunkedFunction(true);
				createNode(nodesByFunction, reference, thunkedFunction);
				continue;
			}

			createNode(nodesByFunction, reference, calledFunction);
		}

		List<GTreeNode> children = nodesByFunction.values()
				.stream()
				.flatMap(list -> list.stream())
				.collect(Collectors.toList());
		results.addAll(children);
	}

	private void createNode(LazyMap<Function, List<GTreeNode>> nodes, Reference reference,
			Function calledFunction) {
		Address fromAddress = reference.getFromAddress();
		if (calledFunction != null) {
			if (isExternalCall(calledFunction)) {
				CallNode node = new ExternalCallNode(calledFunction, fromAddress,
					CallTreePlugin.FUNCTION_ICON, callTreeOptions);
				addNode(nodes, node);
			}
			else {
				addNode(nodes,
					new OutgoingCallNode(program, calledFunction, fromAddress, callTreeOptions));
			}
		}
		else if (isCallReference(reference)) {

			Function externalFunction = getExternalFunctionTempHackWorkaround(reference);
			if (externalFunction != null) {
				CallNode node = new ExternalCallNode(externalFunction, fromAddress,
					CallTreePlugin.FUNCTION_ICON, callTreeOptions);
				addNode(nodes, node);
			}
			else {
				// we have a call reference, but no function
				CallNode node = new DeadEndNode(program, reference, callTreeOptions);
				addNode(nodes, node);
			}
		}
	}

	private Function getExternalFunctionTempHackWorkaround(Reference reference) {
		Address toAddress = reference.getToAddress();
		Listing listing = program.getListing();
		Data data = listing.getDataAt(toAddress);
		if (data == null) {
			return null;
		}

		if (!data.isPointer()) {
			return null;
		}

		Reference primaryReference = data.getPrimaryReference(0); // not sure why 0
		if (primaryReference.isExternalReference()) {
			FunctionManager functionManager = program.getFunctionManager();
			return functionManager.getFunctionAt(primaryReference.getToAddress());
		}
		return null;
	}

	private boolean isExternalCall(Function calledFunction) {
		return calledFunction.isExternal();
	}

	private boolean isCallReference(Reference reference) {
		RefType type = reference.getReferenceType();
		if (type.isCall()) {
			return true;
		}

		if (type.isWrite()) {
			return false;
		}

		Listing listing = program.getListing();
		Instruction instruction = listing.getInstructionAt(reference.getFromAddress());
		if (instruction == null || !instruction.getFlowType().isCall()) {
			return false;
		}

		if (listing.getFunctionAt(reference.getToAddress()) != null) {
			return true;
		}

		Data data = listing.getDataAt(reference.getToAddress());
		if (data == null) {
			return false;
		}

		Reference ref = data.getPrimaryReference(0);
		if (ref == null || !ref.isExternalReference()) {
			return false;
		}

		Symbol extSym = program.getSymbolTable().getPrimarySymbol(ref.getToAddress());
		SymbolType symbolType = extSym.getSymbolType();
		if (symbolType == SymbolType.FUNCTION) {
			return true;
		}
		return false;
	}

	@Override
	public Address getSourceAddress() {
		return sourceAddress;
	}

	@Override
	public ProgramLocation getLocation() {
		return new FunctionSignatureFieldLocation(function.getProgram(), function.getEntryPoint());
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (icon == null) {
			icon = outgoingFunctionIcon;
			if (functionIsInPath()) {
				icon = CallTreePlugin.RECURSIVE_ICON;
			}
		}
		return icon;
	}

	@Override
	boolean functionIsInPath() {
		TreePath path = getTreePath();
		Object[] pathComponents = path.getPath();
		for (Object pathComponent : pathComponents) {
			OutgoingCallNode node = (OutgoingCallNode) pathComponent;
			if (node != this && node.function.equals(function)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getToolTip() {
		return "Called from " + sourceAddress;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}
}
