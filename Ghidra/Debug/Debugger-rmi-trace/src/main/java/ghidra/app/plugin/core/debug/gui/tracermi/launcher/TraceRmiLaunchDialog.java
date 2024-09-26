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

import java.util.List;
import java.util.Map;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.AbstractDebuggerParameterDialog;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.LaunchParameter;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;

public class TraceRmiLaunchDialog extends AbstractDebuggerParameterDialog<LaunchParameter<?>> {

	public TraceRmiLaunchDialog(PluginTool tool, String title, String buttonText, Icon buttonIcon) {
		super(tool, title, buttonText, buttonIcon);
	}

	@Override
	protected String parameterName(LaunchParameter<?> parameter) {
		return parameter.name();
	}

	@Override
	protected Class<?> parameterType(LaunchParameter<?> parameter) {
		return parameter.type();
	}

	@Override
	protected String parameterLabel(LaunchParameter<?> parameter) {
		return parameter.display();
	}

	@Override
	protected String parameterToolTip(LaunchParameter<?> parameter) {
		return parameter.description();
	}

	@Override
	protected ValStr<?> parameterDefault(LaunchParameter<?> parameter) {
		return parameter.defaultValue();
	}

	@Override
	protected List<?> parameterChoices(LaunchParameter<?> parameter) {
		return parameter.choices();
	}

	@Override
	protected Map<String, ValStr<?>> validateArguments(Map<String, LaunchParameter<?>> parameters,
			Map<String, ValStr<?>> arguments) {
		return LaunchParameter.validateArguments(parameters, arguments);
	}

	@Override
	protected void parameterSaveValue(LaunchParameter<?> parameter, SaveState state, String key,
			ValStr<?> value) {
		state.putString(key, value.str());
	}

	@Override
	protected ValStr<?> parameterLoadValue(LaunchParameter<?> parameter, SaveState state,
			String key) {
		String str = state.getString(key, null);
		if (str == null) {
			return null;
		}
		return parameter.decode(str);
	}
}
