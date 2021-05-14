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
package agent.dbgmodel.dbgmodel;

import static org.junit.Assert.assertNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import ghidra.util.Msg;

public class ProcMaker implements AutoCloseable {
	final DebugClient client;
	final DebugControl control;
	final String cmdLine;

	final CompletableFuture<DebugProcessInfo> procInfo = new CompletableFuture<>();
	final CompletableFuture<DebugThreadInfo> threadInfo = new CompletableFuture<>();
	final CompletableFuture<Integer> procExit = new CompletableFuture<>();

	StringBuilder outputCapture = null;

	public ProcMaker(DebugClient client, String cmdLine) {
		this.client = client;
		this.cmdLine = cmdLine;

		this.control = client.getControl();
	}

	public void start() {
		client.setEventCallbacks(new NoisyDebugEventCallbacksAdapter(DebugStatus.NO_CHANGE) {
			@Override
			public DebugStatus createProcess(DebugProcessInfo debugProcessInfo) {
				super.createProcess(debugProcessInfo);
				procInfo.complete(debugProcessInfo);
				return DebugStatus.BREAK;
			}

			@Override
			public DebugStatus createThread(DebugThreadInfo debugThreadInfo) {
				super.createThread(debugThreadInfo);
				threadInfo.complete(debugThreadInfo);
				return DebugStatus.BREAK;
			}

			@Override
			public DebugStatus exitProcess(int exitCode) {
				super.exitProcess(exitCode);
				procExit.complete(exitCode);
				return DebugStatus.BREAK;
			}
		});
		client.setOutputCallbacks(new DebugOutputCallbacks() {
			@Override
			public void output(int mask, String text) {
				System.out.print(text);
				if (outputCapture != null) {
					outputCapture.append(text);
				}
			}
		});

		Msg.debug(this, "Starting " + cmdLine + " with client " + client);
		control.execute(".create " + cmdLine);
		control.waitForEvent();
		DebugProcessInfo pi = procInfo.getNow(null);
		assertNotNull(pi);
		control.execute("g");
		control.waitForEvent();
		DebugThreadInfo ti = threadInfo.getNow(null);
		assertNotNull(ti);
	}

	public void kill() {
		Msg.debug(this, "Killing " + cmdLine);
		control.execute(".kill");
		control.waitForEvent();
		Integer exitCode = procExit.getNow(null);
		client.setOutputCallbacks(null);
		assertNotNull(exitCode);
	}

	public List<String> execCapture(String command) {
		try {
			outputCapture = new StringBuilder();
			control.execute(command);
			return Arrays.asList(outputCapture.toString().split("\n"));
		}
		finally {
			outputCapture = null;
		}
	}

	@Override
	public void close() {
		if (procInfo.isDone() && !procExit.isDone()) {
			kill();
		}
	}
}
