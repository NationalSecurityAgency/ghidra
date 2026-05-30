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
package ghidra.app.plugin.core.debug.service.tracemgr;

import java.io.IOException;
import java.net.ConnectException;
import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin.AskTraceResult;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Trace;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.database.DomainObjectLockHold;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractSaveTraceTask extends Task {
	protected final Trace trace;
	protected final AskTraceResult asked;
	protected final boolean force;
	protected final PluginTool tool;

	protected final CompletableFuture<Void> future = new CompletableFuture<>();

	public AbstractSaveTraceTask(String title, PluginTool tool, Trace trace, AskTraceResult asked,
			boolean force) {
		super(title, true, true, true);
		this.tool = tool;
		this.trace = trace;
		this.asked = asked;
		this.force = force;
	}

	protected DomainObjectLockHold maybeLock(Trace trace, boolean lock) {
		if (!lock) {
			return null;
		}
		return DomainObjectLockHold.forceLock(trace, false, getTaskTitle());
	}

	protected abstract void saveTrace(TaskMonitor monitor)
			throws CancelledException, InvalidNameException, IOException;

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		try (DomainObjectLockHold hold = maybeLock(trace, force)) {
			saveTrace(monitor);
		}
		catch (CancelledException e) {
			// Done
			future.completeExceptionally(e);
		}
		catch (NotConnectedException | ConnectException e) {
			ClientUtil.promptForReconnect(tool.getProject().getRepository(), tool.getToolFrame());
			future.completeExceptionally(e);
		}
		catch (IOException e) {
			ClientUtil.handleException(tool.getProject().getRepository(), e, getTaskTitle(),
				tool.getToolFrame());
			future.completeExceptionally(e);
		}
		catch (InvalidNameException e) {
			Msg.showError(DebuggerTraceManagerServicePlugin.class, null, getTaskTitle(),
				e.getMessage());
			future.completeExceptionally(e);
		}
		catch (Throwable e) {
			Msg.showError(DebuggerTraceManagerServicePlugin.class, null, getTaskTitle(),
				e.getMessage(), e);
			future.completeExceptionally(e);
		}
	}
}
