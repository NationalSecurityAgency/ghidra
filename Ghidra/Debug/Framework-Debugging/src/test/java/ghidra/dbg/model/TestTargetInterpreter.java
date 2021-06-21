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
package ghidra.dbg.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetInterpreter;

public class TestTargetInterpreter
		extends DefaultTestTargetObject<TestTargetObject, TestTargetSession>
		implements TargetInterpreter {

	public class ExecuteCall<T> extends CompletableFuture<T> {
		public final String cmd;

		public ExecuteCall(String cmd) {
			this.cmd = cmd;
		}
	}

	private final Deque<ExecuteCall<Void>> queueExecute = new LinkedList<>();
	private final Deque<ExecuteCall<String>> queueExecuteCapture = new LinkedList<>();

	public TestTargetInterpreter(TestTargetSession parent) {
		super(parent, "Interpreter", "Interpreter");
		changeAttributes(List.of(), Map.of(
			DISPLAY_ATTRIBUTE_NAME, "Test Debugger",
			PROMPT_ATTRIBUTE_NAME, "TEST>>" //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> execute(String cmd) {
		synchronized (queueExecute) {
			ExecuteCall<Void> f = new ExecuteCall<>(cmd);
			queueExecute.offer(f);
			return f;
		}
	}

	@Override
	public CompletableFuture<String> executeCapture(String cmd) {
		synchronized (queueExecuteCapture) {
			ExecuteCall<String> f = new ExecuteCall<>(cmd);
			queueExecuteCapture.offer(f);
			return f;
		}
	}

	public void setDisplay(String display) {
		changeAttributes(List.of(), Map.of(
			DISPLAY_ATTRIBUTE_NAME, display //
		), "Display changed");
	}

	public void setPrompt(String prompt) {
		changeAttributes(List.of(), Map.of(
			PROMPT_ATTRIBUTE_NAME, prompt //
		), "Prompt changed");
	}

	public void output(Channel channel, String line) {
		listeners.fire.consoleOutput(this, channel, line + "\n");
	}

	public void clearCalls() {
		synchronized (queueExecute) {
			queueExecute.clear();
		}
		synchronized (queueExecuteCapture) {
			queueExecuteCapture.clear();
		}
	}

	public ExecuteCall<Void> pollExecute() {
		synchronized (queueExecute) {
			return queueExecute.poll();
		}
	}

	public ExecuteCall<String> pollExecuteCapture() {
		synchronized (queueExecuteCapture) {
			return queueExecuteCapture.poll();
		}
	}
}
