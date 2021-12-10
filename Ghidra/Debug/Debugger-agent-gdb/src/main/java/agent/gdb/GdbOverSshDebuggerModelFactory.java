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

import agent.gdb.model.impl.GdbModelImpl;
import agent.gdb.pty.ssh.GhidraSshPtyFactory;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ShellUtils;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;

@FactoryDescription(
	brief = "GNU gdb via SSH",
	htmlDetails = "Launch a GDB session over an SSH connection")
public class GdbOverSshDebuggerModelFactory implements DebuggerModelFactory {

	private String gdbCmd = "/usr/bin/gdb";
	@FactoryOption("GDB launch command")
	public final Property<String> gdbCommandOption =
		Property.fromAccessors(String.class, this::getGdbCommand, this::setGdbCommand);

	private boolean existing = false;
	@FactoryOption("Use existing session via new-ui")
	public final Property<Boolean> useExistingOption =
		Property.fromAccessors(boolean.class, this::isUseExisting, this::setUseExisting);

	private String hostname = GhidraSshPtyFactory.DEFAULT_HOSTNAME;
	@FactoryOption("SSH hostname")
	public final Property<String> hostnameOption =
		Property.fromAccessors(String.class, this::getHostname, this::setHostname);

	private int port = GhidraSshPtyFactory.DEFAULT_PORT;
	@FactoryOption("SSH TCP port")
	public final Property<Integer> portOption =
		Property.fromAccessors(Integer.class, this::getPort, this::setPort);

	private String username = GhidraSshPtyFactory.DEFAULT_USERNAME;
	@FactoryOption("SSH username")
	public final Property<String> usernameOption =
		Property.fromAccessors(String.class, this::getUsername, this::setUsername);

	private String configFile = GhidraSshPtyFactory.DEFAULT_CONFIG_FILE;
	@FactoryOption("Open SSH config file")
	public final Property<String> keyFileOption =
		Property.fromAccessors(String.class, this::getConfigFile, this::setConfigFile);

	// Always default to false, despite local system, because remote is likely Linux.
	private boolean useCrlf = false;
	@FactoryOption("Use DOS line endings (unchecked for UNIX remote)")
	public final Property<Boolean> crlfNewLineOption =
		Property.fromAccessors(Boolean.class, this::isUseCrlf, this::setUseCrlf);

	@Override
	public CompletableFuture<? extends DebuggerObjectModel> build() {
		List<String> gdbCmdLine = ShellUtils.parseArgs(gdbCmd);
		return CompletableFuture.supplyAsync(() -> {
			GhidraSshPtyFactory factory = new GhidraSshPtyFactory();
			factory.setHostname(hostname);
			factory.setPort(port);
			factory.setConfigFile(configFile);
			factory.setUsername(username);
			return new GdbModelImpl(factory);
		}).thenCompose(model -> {
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
		});
	}

	@Override
	public boolean isCompatible() {
		return true;
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

	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getConfigFile() {
		return configFile;
	}

	public void setConfigFile(String configFile) {
		this.configFile = configFile;
	}

	public boolean isUseCrlf() {
		return useCrlf;
	}

	public void setUseCrlf(boolean useCrlf) {
		this.useCrlf = useCrlf;
	}
}
