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
package ghidra.dbg.jdi.rmi.jpda;

import java.util.Map;

import com.sun.jdi.connect.Connector;
import com.sun.jdi.connect.Connector.Argument;

import ghidra.dbg.jdi.manager.JdiCause.Causes;
import ghidra.dbg.jdi.manager.impl.JdiManagerImpl;
import ghidra.util.Msg;

public class JdiClientThread extends Thread {

	private final Map<String, String> env;
	private final JdiArguments arguments;

	private JdiManagerImpl manager;
	private JdiConnector connector;

	public JdiClientThread(Map<String, String> env) {
		this.env = env;
		this.arguments = new JdiArguments(env);
	}

	@Override
	public void run() {
		try {
			manager = new JdiManagerImpl();
			connector = new JdiConnector(manager, env);

			Connector cx = arguments.getConnector(manager.getVirtualMachineManager());

			Map<String, Argument> args = cx.defaultArguments();
			arguments.putArguments(args);
			if (manager.addVM(cx, args) != null) {
				connector.getCommands().ghidraTraceSyncEnable();
				connector.getHooks().vmStarted(null, Causes.UNCLAIMED);
			}
			else {
				// Nothing. addVM should already have reported the error.
			}
		}
		catch (Exception e) {
			Msg.error(this, "Could not start the JDI client", e);
		}
	}

	public JdiConnector connector() {
		return connector;
	}

	public JdiCommands cmds() {
		return connector.getCommands();
	}
}
