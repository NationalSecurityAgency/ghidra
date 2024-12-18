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

import com.sun.jdi.VirtualMachineManager;
import com.sun.jdi.connect.AttachingConnector;
import com.sun.jdi.connect.Connector;
import com.sun.jdi.connect.Connector.Argument;

import ghidra.dbg.util.ShellUtils;

public class JdiArguments {
	enum Mode {
		ATTACH_PORT, ATTACH_PID, LAUNCH;
	}

	private final Map<String, String> env;
	private final Mode mode;

	public JdiArguments(Map<String, String> env) {
		this.env = Map.copyOf(env);
		this.mode = computeMode();
	}

	/**
	 * Compute/detect the launch mode using the environment map.
	 * 
	 * <p>
	 * It'd be nice if this were selected/specified in the script body, rather than by what options
	 * are present in its header. The reason we can't, though, is that the JDI client thread needs
	 * to also work within Ghidra's JVM, i.e., without launching a jshell subprocess. By far, the
	 * simplest way to accomplish this is to keep all the logic here, and just pass the environment
	 * map in. For the jshell-subprocess case, it's the environment map proper. For the
	 * in-Ghidra's-VM case, it's the map we would have passed when creating the subprocess.
	 * 
	 * @return the mode.
	 */
	protected Mode computeMode() {
		if (env.containsKey("OPT_PORT")) {
			return Mode.ATTACH_PORT;
		}
		if (env.containsKey("OPT_PID")) {
			return Mode.ATTACH_PID;
		}
		return Mode.LAUNCH;
	}

	protected AttachingConnector findConnectorByArgKey(VirtualMachineManager vmm, String key) {
		return vmm.attachingConnectors()
				.stream()
				.filter(ac -> ac.defaultArguments().containsKey(key))
				.findFirst()
				.orElseThrow();
	}

	public Connector getConnector(VirtualMachineManager vmm) {
		return switch (mode) {
			case ATTACH_PORT -> findConnectorByArgKey(vmm, "port");
			case ATTACH_PID -> findConnectorByArgKey(vmm, "pid");
			case LAUNCH -> vmm.defaultConnector();
		};
	}

	public void putArguments(Map<String, Argument> args) {
		switch (mode) {
			case ATTACH_PORT -> {
				args.get("hostname").setValue(env.get("OPT_HOST").toString());
				args.get("port").setValue(env.get("OPT_PORT").toString());
				args.get("timeout").setValue(env.get("OPT_TIMEOUT").toString());
			}
			case ATTACH_PID -> {
				args.get("pid").setValue(env.get("OPT_PID").toString());
				args.get("timeout").setValue(env.get("OPT_TIMEOUT").toString());
			}
			case LAUNCH -> {
				args.get("main").setValue(env.get("OPT_TARGET_CLASS"));
				Argument argSuspend = args.get("suspend");
				String optSuspend = env.get("OPT_SUSPEND");
				if (argSuspend != null && optSuspend != null) {
					argSuspend.setValue(optSuspend);
				}
				Argument argIncludeVirtualThreads = args.get("includevirtualthreads");
				String optInclude = env.get("OPT_INCLUDE");
				if (argIncludeVirtualThreads != null && optInclude != null) {
					argIncludeVirtualThreads.setValue(optInclude);
				}
				String cp = env.get("OPT_TARGET_CLASSPATH");
				if (!cp.isBlank()) {
					args.get("options").setValue("-cp " + ShellUtils.generateArgument(cp));
				}
			}
		}
	}
}
