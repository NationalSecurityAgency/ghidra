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
package agent.lldb.model.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.lldb.model.iface2.LldbModelTargetConnector;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "ProcessLaunchWithOptionsConnector",
	elements = { //
		@TargetElementType(type = Void.class) //
	},
	attributes = { //
		@TargetAttributeType(type = Void.class) //
	})
public class LldbModelTargetProcessLaunchWithOptionsConnectorImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetConnector {

	protected final LldbModelTargetConnectorContainerImpl connectors;
	protected final TargetParameterMap paramDescs;

	public LldbModelTargetProcessLaunchWithOptionsConnectorImpl(
			LldbModelTargetConnectorContainerImpl connectors,
			String name) {
		super(connectors.getModel(), connectors, name, name);
		this.connectors = connectors;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME,
			paramDescs = TargetParameterMap.copyOf(computeParameters()) //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> setActive() {
		connectors.setDefaultConnector(this);
		return CompletableFuture.completedFuture(null);
	}

	protected Map<String, ParameterDescription<?>> computeParameters() {
		HashMap<String, ParameterDescription<?>> map =
			new LinkedHashMap<String, ParameterDescription<?>>();
		ParameterDescription<String> p0 = ParameterDescription.create(String.class, "File", true,
			"", "File", "executable to be launched");
		map.put("File", p0);
		ParameterDescription<String> p1 = ParameterDescription.create(String.class, "Args", false,
			"", "Args", "command-line arguments");
		map.put("Args", p1);
		ParameterDescription<String> p2 = ParameterDescription.create(String.class, "Env", false,
			"", "Env", "environment arguments");
		map.put("Env", p2);
		ParameterDescription<String> p3 = ParameterDescription.create(String.class, "STDIN", false,
			"", "STDIN", "path for STDIN");
		map.put("STDIN", p3);
		ParameterDescription<String> p4 = ParameterDescription.create(String.class, "STDOUT", false,
			"", "STDOUT", "path for STDOUT");
		map.put("STDOUT", p4);
		ParameterDescription<String> p5 = ParameterDescription.create(String.class, "STDERR", false,
			"", "STDERR", "path for STDERR");
		map.put("STDERR", p5);
		ParameterDescription<String> p6 = ParameterDescription.create(String.class, "Dir", false,
			"", "Dir", "working directory");
		map.put("Dir", p6);

		ParameterDescription<Boolean> pF0 = ParameterDescription.create(Boolean.class, "Exec",
			false,
			false, "Exec", "exec when launching and turn the calling process into a new process");
		map.put("Exec", pF0);
		ParameterDescription<Boolean> pF1 =
			ParameterDescription.create(Boolean.class, "BreakOnLaunch", false,
				true, "Break on launch",
				"stop as soon as the process launches to allow the process to be debugged");
		map.put("BreakOnLaunch", pF1);
		ParameterDescription<Boolean> pF2 = ParameterDescription.create(Boolean.class,
			"BreakOnEntry", false,
			true, "Break on entry", "stop at the program entry point instead of auto-continuing");
		map.put("BreakOnEntry", pF2);
		ParameterDescription<Boolean> pF3 =
			ParameterDescription.create(Boolean.class, "ASLR", false,
				false, "Disable ASLR", "disable Address Space Layout Randomization (ASLR)");
		map.put("ASLR", pF3);
		ParameterDescription<Boolean> pF4 =
			ParameterDescription.create(Boolean.class, "STDIO", false,
				false, "Disable STDIO", "disable stdio for inferior process (e.g. for a GUI app)");
		map.put("STDIO", pF4);
		ParameterDescription<Boolean> pF5 =
			ParameterDescription.create(Boolean.class, "NewTTY", false,
				false, "New TTY", "launch the process in a new TTY if supported by the host");
		map.put("NewTTY", pF5);
		ParameterDescription<Boolean> pF6 = ParameterDescription.create(Boolean.class, "Shell",
			false,
			false, "Launch from shell", "launch the process inside a shell to get shell expansion");
		map.put("Shell", pF6);
		ParameterDescription<Boolean> pF7 = ParameterDescription.create(Boolean.class, "NewGroup",
			false,
			false, "New group",
			"launch the process in a separate process group if you are going to hand the process off (e.g. to debugserver)");
		map.put("NewGroup", pF7);
		ParameterDescription<Boolean> pF8 =
			ParameterDescription.create(Boolean.class, "ExitRace", false,
				false, "Suppress race on exit",
				"set this flag so lldb & the handee don’t race to set its exit status");
		map.put("ExitRace", pF8);
		ParameterDescription<Boolean> pF9 = ParameterDescription.create(Boolean.class, "Detach",
			false,
			false, "Detach on disconnect",
			"client stub should detach rather than killing the debugee if it loses connection with lldb");
		map.put("Detach", pF9);
		ParameterDescription<Boolean> pFA =
			ParameterDescription.create(Boolean.class, "ExpandArgs", false,
				false, "Shell-style expansion", "perform shell-style argument expansion");
		map.put("ExpandArgs", pFA);
		ParameterDescription<Boolean> pFB =
			ParameterDescription.create(Boolean.class, "CloseTTY", false,
				false, "Close TTY on exit", "close the open TTY on exit");
		map.put("CloseTTY", pFB);
		ParameterDescription<Boolean> pFC =
			ParameterDescription.create(Boolean.class, "Inherit", false,
				false, "Inherit TCC", "inherit TCC permissions from the parent");
		map.put("Inherit", pFC);
		return map;
	}

	@Override
	public TargetParameterMap getParameters() {
		return TargetMethod.getParameters(this);
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			getManager().launch(args).handle(seq::nextIgnore);
		}).finish().exceptionally((exc) -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}
}
