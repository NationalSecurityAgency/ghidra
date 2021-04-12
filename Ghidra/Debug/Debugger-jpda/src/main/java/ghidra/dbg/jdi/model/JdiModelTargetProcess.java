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
package ghidra.dbg.jdi.model;

import java.io.*;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.jdi.manager.JdiConsoleOutputListener;
import ghidra.dbg.jdi.model.iface1.JdiModelSelectableObject;
import ghidra.dbg.jdi.model.iface1.JdiModelTargetConsole;
import ghidra.dbg.target.TargetConsole;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.*;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "Process",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(name = "state", type = TargetExecutionState.class, hidden = true),
		@TargetAttributeType(type = Void.class)
	})
public class JdiModelTargetProcess extends JdiModelTargetObjectImpl
		implements JdiModelTargetConsole, JdiConsoleOutputListener, JdiModelSelectableObject {

	public static String getUniqueId(Process obj) {
		return Long.toHexString(obj.pid());
	}

	static String STATE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "state";

	protected final Process process;

	//private PrintWriter writer;
	private Thread input;
	private Thread error;

	public JdiModelTargetProcess(JdiModelTargetVM vm, Process process, boolean isElement) {
		super(vm, getUniqueId(process), process, isElement);
		this.process = process;

		//writer = new PrintWriter(process.getOutputStream());
		input = new Thread(() -> readStream(process.getInputStream(), TargetConsole.Channel.STDOUT),
			"JDI process input reader");
		input.start();
		error = new Thread(() -> readStream(process.getErrorStream(), TargetConsole.Channel.STDERR),
			"JDI process error reader");
		error.start();

		changeAttributes(List.of(), List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, convertState(process.isAlive()), //
			DISPLAY_ATTRIBUTE_NAME, getDisplay() //
		), "Initialized");
	}

	@Override
	public String getDisplay() {
		if (process == null) {
			return super.getDisplay();
		}
		StringBuilder sb = new StringBuilder();
		sb.append("Process " + process.pid());
		sb.append(" alive=");
		sb.append(process.isAlive());
		return sb.toString();
	}

	protected TargetExecutionState convertState(boolean isAlive) {
		return isAlive ? TargetExecutionState.ALIVE : TargetExecutionState.TERMINATED;
	}

	@Override
	@Internal
	public CompletableFuture<Void> setActive() {
		return CompletableFuture.completedFuture(null);
		///return thread.select();
	}

	@Override
	public void output(TargetConsole.Channel channel, String out) {
		switch (channel) {
			case STDOUT:
				channel = TargetConsole.Channel.STDOUT;
				break;
			case STDERR:
				channel = TargetConsole.Channel.STDERR;
				break;
			default:
				throw new AssertionError();
		}
		listeners.fire.consoleOutput(this, channel, out);
	}

	private void readStream(InputStream in, TargetConsole.Channel channel) {
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		try {
			String line;
			while (process.isAlive() && null != (line = reader.readLine())) {
				System.err.println(line);
				output(channel, line);
			}
		}
		catch (Throwable e) {
			Msg.debug(this, channel + ", reader exiting because " + e);
			//throw new AssertionError(e);
		}
	}

	@Override
	public CompletableFuture<Void> write(byte[] data) {
		// TODO Auto-generated method stub
		return null;
	}
}
