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
package ghidra.app.plugin.core.functiongraph.mvc;

import ghidra.app.plugin.core.functiongraph.graph.FunctionGraphFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.IsolatedEntrySubModel;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.SwingRunnable;
import ghidra.util.task.TaskMonitor;

public class FunctionGraphRunnable implements SwingRunnable {

	private final FGController controller;
	private final FGModel model;
	private final ProgramLocation location;
	private final Program program;
	private final Function function;

	private FGData graphData;
	private TaskMonitor taskMonitor;

	public FunctionGraphRunnable(FGController controller, Program program,
			ProgramLocation location) {

		if (location == null) {
			throw new NullPointerException("Location cannot be null");
		}

		if (program == null) {
			throw new NullPointerException("Program cannot be null");
		}

		this.controller = controller;
		this.model = controller.getModel();
		this.program = program;
		this.location = location;

		FunctionManager functionManager = program.getFunctionManager();
		this.function = functionManager.getFunctionContaining(location.getAddress());
	}

	boolean containsLocation(ProgramLocation programLocation) {
		if (function == null) {
			return false;
		}
		return function.getBody().contains(programLocation.getAddress());
	}

	ProgramLocation getLocation() {
		return location;
	}

	@Override
	public void swingRun(boolean isCancelled) {
		if (isCancelled) {
			graphData = new EmptyFunctionGraphData(
				"Graph cancelled for location: " + location.getAddress());
		}
		else if (program.isClosed()) {
			// can happen when closing a program with results waiting to get onto the Swing thread
			graphData = new EmptyFunctionGraphData("Program closed: " + location.getAddress());
		}
		else if (graphData == null) {
			graphData = new EmptyFunctionGraphData("No Function at " + location.getAddress());
		}
		model.setFunctionGraphData(this, graphData);
	}

	@Override
	public void monitoredRun(TaskMonitor monitor) {
		this.taskMonitor = monitor;
		monitor.setProgress(0);

		Function validatedFunction = validateFunction(function, location.getAddress());
		if (validatedFunction == null) {
			String message = "Location is not in a defined or undefined function \"" +
				location.getAddress() + "\"";
			graphData = new EmptyFunctionGraphData(message);
			monitor.setMessage(message);
			return;
		}

		monitor.setMessage("Creating graph for \"" + validatedFunction.getName() + "\"");
		monitor.setProgress(0);
		try {
			graphData = FunctionGraphFactory.createNewGraph(validatedFunction, controller,
				program, monitor);
			monitor.setMessage(
				"Finished creating graph for \"" + validatedFunction.getName() + "\"");
		}
		catch (CancelledException e) {
			String message = "Cancelled graph for \"" + validatedFunction.getName() + "\"";
			graphData = new EmptyFunctionGraphData(message);
			monitor.setMessage(message);
		}
	}

	private Function validateFunction(Function currentFunction, Address address) {
		if (currentFunction != null) {
			return currentFunction;
		}

		return findFunctionUsingIsolatedBlockModel(address);
	}

	private Function findFunctionUsingIsolatedBlockModel(Address address) {
		taskMonitor.setMessage("Locating undefined function entry using Isolated Entry model...");
		try {
			IsolatedEntrySubModel blockModel = new IsolatedEntrySubModel(program);
			CodeBlock codeBlock = blockModel.getFirstCodeBlockContaining(address, taskMonitor);
			if (codeBlock == null) {
				return null;
			}

			// function may not contain currentAddress in its body. 
			// This will cause provider to re-decompile when 
			// clicking around the currentAddress :(
			Address entry = codeBlock.getFirstStartAddress();
			Function newFunction = program.getFunctionManager().getFunctionAt(entry);
			if (newFunction != null) {
				return newFunction;
			}
			UndefinedFunction undefinedFunction = new UndefinedFunction(program, entry);
			undefinedFunction.setBody(codeBlock);
			return undefinedFunction;
		}
		catch (CancelledException e) {
			return null;
		}
	}
}
