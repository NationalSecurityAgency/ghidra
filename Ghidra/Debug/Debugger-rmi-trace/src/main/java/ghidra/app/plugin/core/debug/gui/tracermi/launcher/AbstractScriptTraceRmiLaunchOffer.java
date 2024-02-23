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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import java.io.File;
import java.net.SocketAddress;
import java.util.*;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.tracermi.launcher.ScriptAttributesParser.ScriptAttributes;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.ScriptAttributesParser.TtyCondition;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.debug.api.tracermi.TerminalSession;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractScriptTraceRmiLaunchOffer extends AbstractTraceRmiLaunchOffer {

	protected final File script;
	protected final String configName;
	protected final ScriptAttributes attrs;

	public AbstractScriptTraceRmiLaunchOffer(TraceRmiLauncherServicePlugin plugin, Program program,
			File script, String configName, ScriptAttributes attrs) {
		super(plugin, program);
		this.script = script;
		this.configName = configName;
		this.attrs = attrs;
	}

	@Override
	public String getConfigName() {
		return configName;
	}

	@Override
	public String getTitle() {
		return attrs.title();
	}

	@Override
	public String getDescription() {
		return attrs.description();
	}

	@Override
	public List<String> getMenuPath() {
		return attrs.menuPath();
	}

	@Override
	public String getMenuGroup() {
		return attrs.menuGroup();
	}

	@Override
	public String getMenuOrder() {
		return attrs.menuOrder();
	}

	@Override
	public Icon getIcon() {
		return attrs.icon();
	}

	@Override
	public HelpLocation getHelpLocation() {
		return attrs.helpLocation();
	}

	@Override
	public Map<String, ParameterDescription<?>> getParameters() {
		return attrs.parameters();
	}

	@Override
	protected int getConnectionTimeoutMillis() {
		return attrs.timeoutMillis();
	}

	protected abstract void prepareSubprocess(List<String> commandLine, Map<String, String> env,
			Map<String, ?> args, SocketAddress address);

	@Override
	protected void launchBackEnd(TaskMonitor monitor, Map<String, TerminalSession> sessions,
			Map<String, ?> args, SocketAddress address) throws Exception {
		List<String> commandLine = new ArrayList<>();
		Map<String, String> env = new HashMap<>(System.getenv());
		prepareSubprocess(commandLine, env, args, address);

		for (Map.Entry<String, TtyCondition> ent : attrs.extraTtys().entrySet()) {
			if (!ent.getValue().isActive(args)) {
				continue;
			}
			NullPtyTerminalSession ns = nullPtyTerminal();
			env.put(ent.getKey(), ns.name());
			sessions.put(ns.name(), ns);
		}

		sessions.put("Shell",
			runInTerminal(commandLine, env, script.getParentFile(), sessions.values()));
	}
}
