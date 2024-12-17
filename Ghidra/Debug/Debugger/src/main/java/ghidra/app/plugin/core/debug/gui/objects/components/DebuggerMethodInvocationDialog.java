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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.util.Map;
import java.util.Set;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.AbstractDebuggerParameterDialog;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.debug.api.ValStr;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigStateField;
import ghidra.framework.plugintool.PluginTool;

@Deprecated(forRemoval = true, since = "11.3")
public class DebuggerMethodInvocationDialog
		extends AbstractDebuggerParameterDialog<ParameterDescription<?>> {

	public DebuggerMethodInvocationDialog(PluginTool tool, String title, String buttonText,
			Icon buttonIcon) {
		super(tool, title, buttonText, buttonIcon);
	}

	@Override
	protected String parameterName(ParameterDescription<?> parameter) {
		return parameter.name;
	}

	@Override
	protected Class<?> parameterType(ParameterDescription<?> parameter) {
		return parameter.type;
	}

	@Override
	protected String parameterLabel(ParameterDescription<?> parameter) {
		return parameter.display;
	}

	@Override
	protected String parameterToolTip(ParameterDescription<?> parameter) {
		return parameter.description;
	}

	@Override
	protected ValStr<?> parameterDefault(ParameterDescription<?> parameter) {
		return ValStr.from(parameter.defaultValue);
	}

	@Override
	protected Set<?> parameterChoices(ParameterDescription<?> parameter) {
		return parameter.choices;
	}

	@Override
	protected Map<String, ValStr<?>> validateArguments(
			Map<String, ParameterDescription<?>> parameters, Map<String, ValStr<?>> arguments) {
		Map<String, ?> args = ValStr.toPlainMap(arguments);
		return ValStr.fromPlainMap(TargetMethod.validateArguments(parameters, args, false));
	}

	@Override
	protected void parameterSaveValue(ParameterDescription<?> parameter, SaveState state,
			String key, ValStr<?> value) {
		ConfigStateField.putState(state, parameter.type.asSubclass(Object.class), key, value.val());
	}

	@Override
	protected ValStr<?> parameterLoadValue(ParameterDescription<?> parameter, SaveState state,
			String key) {
		return ValStr.from(ConfigStateField.getState(state, parameter.type, key));
	}
}
