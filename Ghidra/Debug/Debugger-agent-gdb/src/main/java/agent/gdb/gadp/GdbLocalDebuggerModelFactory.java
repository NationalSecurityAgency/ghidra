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
package agent.gdb.gadp;

import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.util.List;

import agent.gdb.manager.GdbManager;
import ghidra.dbg.gadp.server.AbstractGadpLocalDebuggerModelFactory;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import ghidra.util.classfinder.ExtensionPointProperties;

@FactoryDescription( //
		brief = "GNU gdb local agent via GADP/TCP", //
		htmlDetails = "Launch a new agent using GDB. This may start a new session or join an existing one." //
)
@ExtensionPointProperties(priority = 100)
public class GdbLocalDebuggerModelFactory extends AbstractGadpLocalDebuggerModelFactory {
	public static boolean checkGdbPresent(String gdbCmd) {
		try {
			ProcessBuilder builder = new ProcessBuilder(gdbCmd, "--version");
			builder.redirectError(Redirect.INHERIT);
			builder.redirectOutput(Redirect.INHERIT);
			@SuppressWarnings("unused")
			Process gdb = builder.start();
			// TODO: Once supported versions are decided, check the version.
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	protected Boolean isSuitable;

	private String gdbCmd = GdbManager.DEFAULT_GDB_CMD;
	@FactoryOption("GDB launch command")
	public final Property<String> gdbCommandOption =
		Property.fromAccessors(String.class, this::getGdbCommand, this::setGdbCommand);

	private boolean existing = false;
	@FactoryOption("Use existing session via new-ui")
	public final Property<Boolean> useExistingOption =
		Property.fromAccessors(boolean.class, this::isUseExisting, this::setUseExisting);

	// TODO: A factory which connects to GDB via SSH. Would need to refactor manager.

	@Override
	public boolean isCompatible() {
		// TODO: Could potentially support GDB on Windows, but the pty thing would need porting.
		if (isSuitable != null) {
			return isSuitable;
		}
		return isSuitable = checkGdbPresent(gdbCmd);
	}

	public String getGdbCommand() {
		return gdbCmd;
	}

	public void setGdbCommand(String gdbCmd) {
		this.gdbCmd = gdbCmd;
	}

	public boolean isUseExisting() {
		return existing;
	}

	public void setUseExisting(boolean existing) {
		this.existing = existing;
		gdbCommandOption.setEnabled(!existing);
	}

	@Override
	protected String getThreadName() {
		return "Local gdb Agent stdout";
	}

	@Override
	protected void completeCommandLine(List<String> cmd) {
		cmd.add(GdbGadpServer.class.getCanonicalName());
		// TODO: Option for additional GDB command-line parameters
		cmd.add("--gadp-args");
		cmd.addAll(List.of("-H", host));
		cmd.addAll(List.of("-p", Integer.toString(port))); // Available ephemeral port
		if (!existing) {
			cmd.addAll(List.of("-g", gdbCmd));
		}
		else {
			cmd.add("-x");
		}
	}
}
