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
package agent.gdb;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbManager;
import agent.gdb.model.impl.GdbModelImpl;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import ghidra.dbg.util.ShellUtils;
import ghidra.program.model.listing.Program;
import ghidra.pty.PtyFactory;

@FactoryDescription(
	brief = "gdb",
	htmlDetails = """
			Connect to gdb.
			This is best for most Linux and Unix userspace targets, and many embedded targets.
			It may also be used with gdbserver by connecting to gdb, then using <code>target remote
			...</code>.
			This will access the native API, which may put Ghidra's JVM at risk.""")
public class GdbInJvmDebuggerModelFactory implements DebuggerModelFactory {

	private String gdbCmd = GdbManager.DEFAULT_GDB_CMD;
	@FactoryOption("GDB launch command")
	public final Property<String> gdbCommandOption =
		Property.fromAccessors(String.class, this::getGdbCommand, this::setGdbCommand);

	private boolean existing = false;
	@FactoryOption("Use existing session via new-ui")
	public final Property<Boolean> useExistingOption =
		Property.fromAccessors(boolean.class, this::isUseExisting, this::setUseExisting);

	private boolean useCrlf = System.lineSeparator().equals("\r\n");;
	@FactoryOption("Use DOS line endings (unchecked for UNIX and Cygwin))")
	public final Property<Boolean> crlfNewLineOption =
		Property.fromAccessors(Boolean.class, this::isUseCrlf, this::setUseCrlf);

	@Override
	public CompletableFuture<? extends DebuggerObjectModel> build() {
		List<String> gdbCmdLine = ShellUtils.parseArgs(gdbCmd);
		GdbModelImpl model = new GdbModelImpl(PtyFactory.local());
		if (useCrlf) {
			model.setDosNewLine();
		}
		else {
			model.setUnixNewLine();
		}
		return model
				.startGDB(existing ? null : gdbCmdLine.get(0),
					gdbCmdLine.subList(1, gdbCmdLine.size()).toArray(String[]::new))
				.thenApply(__ -> model);
	}

	public boolean isUseCrlf() {
		return useCrlf;
	}

	public void setUseCrlf(boolean useCrlf) {
		this.useCrlf = useCrlf;
	}

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
		return 80;
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
}
