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

import java.util.List;

import agent.gdb.GdbCompatibility;
import agent.gdb.manager.GdbManager;
import ghidra.dbg.gadp.server.AbstractGadpLocalDebuggerModelFactory;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import ghidra.dbg.util.ShellUtils;
import ghidra.program.model.listing.Program;

@FactoryDescription(
	brief = "gdb via GADP",
	htmlDetails = """
			Connect to gdb.
			This is best for most Linux and Unix userspace targets, and many embedded targets.
			This will protect Ghidra's JVM by using a subprocess to access the native API.
			If you are using <b>gdbserver</b>, you must connect to gdb first (consider the non-GADP
			connector), then use <code>target remote ...</code> to connect to your target.""")
public class GdbGadpDebuggerModelFactory extends AbstractGadpLocalDebuggerModelFactory {

	private String gdbCmd = GdbManager.DEFAULT_GDB_CMD;
	@FactoryOption("GDB launch command")
	public final Property<String> gdbCommandOption =
		Property.fromAccessors(String.class, this::getGdbCommand, this::setGdbCommand);

	private boolean existing = false;
	@FactoryOption("Use existing session via new-ui")
	public final Property<Boolean> useExistingOption =
		Property.fromAccessors(boolean.class, this::isUseExisting, this::setUseExisting);

	// TODO: newLine option?

	@Override
	public int getPriority(Program program) {
		if (!GdbCompatibility.INSTANCE.isCompatible(gdbCmd)) {
			return -1;
		}
		if (program != null) {
			String exe = program.getExecutablePath();
			if (exe == null || exe.isBlank()) {
				return -1;
			}
		}
		return 60;
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
		List<String> gdbCmdLine = ShellUtils.parseArgs(gdbCmd);
		cmd.add(GdbGadpServer.class.getCanonicalName());
		if (!existing && gdbCmdLine.size() >= 2) {
			cmd.addAll(gdbCmdLine.subList(1, gdbCmdLine.size()));
		}
		cmd.add("--agent-args");
		cmd.addAll(List.of("-H", host));
		cmd.addAll(List.of("-p", Integer.toString(port))); // Available ephemeral port
		if (!existing && gdbCmdLine.size() >= 1) {
			cmd.add("-g");
			cmd.add(gdbCmdLine.get(0));
		}
		else {
			cmd.add("-x");
		}
	}
}
