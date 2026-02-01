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
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.LaunchParameter;
import ghidra.debug.api.tracermi.TerminalSession;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
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
	public Map<String, LaunchParameter<?>> getParameters() {
		return attrs.parameters();
	}

	@Override
	protected int getConnectionTimeoutMillis() {
		return attrs.timeoutMillis();
	}

	protected void prepareSubprocess(List<String> commandLine, Map<String, String> env,
			Map<String, ValStr<?>> args, SocketAddress address) {
		ScriptAttributesParser.processArguments(commandLine, env, script, attrs.parameters(), args,
			attrs.dependencies(), address);
	}

	@Override
	protected TraceRmiBackEnd launchBackEnd(TaskMonitor monitor,
			Map<String, TerminalSession> sessions, Map<String, ValStr<?>> args,
			SocketAddress address) throws Exception {
		List<String> commandLine = new ArrayList<>();
		Map<String, String> env = new HashMap<>(System.getenv());
		prepareSubprocess(commandLine, env, args, address);
		if (program != null) {
			LaunchParameter<?> imageParameter = imageParameter();
			if (imageParameter != null) {
				ValStr<?> valStr = args.get(imageParameter.name());
				if (valStr != null && !valStr.str().contains(program.getName())) {
					Msg.warn(this,
						"Possible mismatch for " + program.getName() + ": " + valStr.str());
				}
			}
			env.put("GHIDRA_LANGUAGE_ID", program.getLanguageID().toString());
		}

		for (Map.Entry<String, TtyCondition> ent : attrs.extraTtys().entrySet()) {
			if (!ent.getValue().isActive(args)) {
				continue;
			}
			NullPtyTerminalSession ns = nullPtyTerminal();
			env.put(ent.getKey(), ns.name());
			sessions.put(ent.getKey(), ns);
		}

		PtyTerminalSession session =
			runInTerminal(commandLine, env, script.getParentFile(), sessions.values());
		sessions.put("Shell", session);
		TraceRmiBackEnd result = new TraceRmiBackEnd();
		session.terminal().addTerminalListener(result);
		return result;
	}

	@Override
	public LaunchParameter<?> imageParameter() {
		return attrs.imageOpt();
	}
}
