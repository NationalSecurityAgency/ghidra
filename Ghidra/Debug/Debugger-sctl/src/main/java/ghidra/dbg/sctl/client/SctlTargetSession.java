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
package ghidra.dbg.sctl.client;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.exception.ExceptionUtils;

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.error.DebuggerModelNoSuchPathException;
import ghidra.dbg.error.DebuggerModelTypeException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.util.PathUtils;

public class SctlTargetSession extends DefaultTargetModelRoot implements
		TargetAttacher<SctlTargetSession>,
		TargetFocusScope<SctlTargetSession>,
		TargetInterpreter<SctlTargetSession>,
		TargetCmdLineLauncher<SctlTargetSession> {

	protected final SctlClient client;

	protected final SctlTargetAttachableContainer attachable;
	protected final SctlTargetProcessContainer processes;
	protected final SctlTargetObjectsContainer objects;

	public SctlTargetSession(SctlClient client) {
		super(client, "Session");
		this.client = client;

		attachable = new SctlTargetAttachableContainer(this);
		processes = new SctlTargetProcessContainer(this);
		objects = new SctlTargetObjectsContainer(this);

		changeAttributes(List.of(), Map.of( //
			attachable.getName(), attachable, //
			processes.getName(), processes, //
			objects.getName(), objects //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return client.attach(pid).thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> attach(TypedTargetObjectRef<? extends TargetAttachable<?>> ref) {
		client.assertMine(TargetObjectRef.class, ref);
		// NOTE: These can change at any time. Just use the path to derive the target PID
		if (!Objects.equals(PathUtils.parent(ref.getPath()), attachable.getPath())) {
			throw new DebuggerModelTypeException(
				"Target of attach must be a child of " + attachable.getPath());
		}
		long pid;
		try {
			pid = Long.parseLong(ref.getIndex());
		}
		catch (IllegalArgumentException e) {
			throw new DebuggerModelNoSuchPathException("Badly-formatted PID", e);
		}
		return client.attach(pid).thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> execute(String cmd) {
		return executeCapture(cmd).thenAccept((out) -> {
			// TODO/HACK: This (re)direction should be done by the agent, not the client
			// TODO: Need a flag in EXEC command indicating capture
			listeners.fire(TargetInterpreterListener.class)
					.consoleOutput(this, Channel.STDOUT, out);
		}).exceptionally(e -> {
			// TODO: Again, non-captured error output should be sent via Aevent by agent
			listeners.fire(TargetInterpreterListener.class)
					.consoleOutput(this, Channel.STDERR, e.getMessage() + "\n");
			return ExceptionUtils.rethrow(e);
		});
	}

	@Override
	public CompletableFuture<String> executeCapture(String cmd) {
		return client.executeCapture(cmd);
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		return client.launch(args).thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> requestFocus(TargetObjectRef ref) {
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			getModel().fetchModelObject(ref.getPath()).handle(seq::next);
		}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
			if (!(obj instanceof SctlTargetThread)) {
				throw new DebuggerModelTypeException("Can only focus threads");
			}
			SctlTargetThread thread = (SctlTargetThread) obj;
			thread.process.client.focusThread(thread.ctlid).handle(seq::exit);
		}).finish();
	}

	protected void fireConsoleOutput(Channel channel, String out) {
		listeners.fire(TargetInterpreterListener.class).consoleOutput(this, channel, out);
	}

	protected void fireFocused(TargetObject focused) {
		changeAttributes(List.of(), Map.of( //
			FOCUS_ATTRIBUTE_NAME, focused //
		), "Focus changed");
		listeners.fire(TargetFocusScopeListener.class).focusChanged(this, focused);
	}
}
