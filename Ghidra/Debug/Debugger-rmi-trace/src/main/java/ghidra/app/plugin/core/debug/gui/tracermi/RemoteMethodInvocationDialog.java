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
package ghidra.app.plugin.core.debug.gui.tracermi;

import java.awt.Component;
import java.beans.*;
import java.util.*;

import javax.swing.Icon;
import javax.swing.JLabel;

import ghidra.app.plugin.core.debug.gui.AbstractDebuggerParameterDialog;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiTarget.Missing;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.RemoteParameter;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigStateField;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.target.TraceObject;

public class RemoteMethodInvocationDialog extends AbstractDebuggerParameterDialog<RemoteParameter> {

	/**
	 * TODO: Make this a proper editor which can browse and select objects of a required schema.
	 */
	public static class TraceObjectEditor extends PropertyEditorSupport {
		private final JLabel unmodifiableField = new JLabel();

		@Override
		public void setValue(Object value) {
			super.setValue(value);
			if (value == null) {
				unmodifiableField.setText("");
				return;
			}
			if (!(value instanceof TraceObject obj)) {
				throw new IllegalArgumentException();
			}
			unmodifiableField.setText(obj.getCanonicalPath().toString());
		}

		@Override
		public boolean supportsCustomEditor() {
			return true;
		}

		@Override
		public Component getCustomEditor() {
			return unmodifiableField;
		}
	}

	static {
		PropertyEditorManager.registerEditor(TraceObject.class, TraceObjectEditor.class);
	}

	private final SchemaContext ctx;

	public RemoteMethodInvocationDialog(PluginTool tool, SchemaContext ctx, String title,
			String buttonText, Icon buttonIcon) {
		super(tool, title, buttonText, buttonIcon);
		this.ctx = ctx;
	}

	@Override
	protected String parameterName(RemoteParameter parameter) {
		return parameter.name();
	}

	@Override
	protected Class<?> parameterType(RemoteParameter parameter) {
		Class<?> type = ctx.getSchema(parameter.type()).getType();
		if (TargetObject.class.isAssignableFrom(type)) {
			return TraceObject.class;
		}
		return type;
	}

	@Override
	protected String parameterLabel(RemoteParameter parameter) {
		return "".equals(parameter.display()) ? parameter.name() : parameter.display();
	}

	@Override
	protected String parameterToolTip(RemoteParameter parameter) {
		return parameter.description();
	}

	@Override
	protected ValStr<?> parameterDefault(RemoteParameter parameter) {
		return ValStr.from(parameter.getDefaultValue());
	}

	@Override
	protected Collection<?> parameterChoices(RemoteParameter parameter) {
		return Set.of();
	}

	@Override
	protected Map<String, ValStr<?>> validateArguments(Map<String, RemoteParameter> parameters,
			Map<String, ValStr<?>> arguments) {
		return arguments;
	}

	@Override
	protected void parameterSaveValue(RemoteParameter parameter, SaveState state, String key,
			ValStr<?> value) {
		ConfigStateField.putState(state, parameterType(parameter).asSubclass(Object.class), key,
			value.val());
	}

	@Override
	protected ValStr<?> parameterLoadValue(RemoteParameter parameter, SaveState state, String key) {
		return ValStr.from(
			ConfigStateField.getState(state, parameterType(parameter), key));
	}

	protected ValStr<?> forMissingDefault(RemoteParameter param) {
		Class<?> type = parameterType(param);
		if (type == Boolean.class || type == boolean.class) {
			return ValStr.from(false);
		}
		return new ValStr<>(null, "");
	}

	@Override
	protected void setEditorValue(PropertyEditor editor, RemoteParameter param, ValStr<?> val) {
		ValStr<?> v = switch (val.val()) {
			case null -> forMissingDefault(param);
			case Missing __ -> forMissingDefault(param);
			case TraceObject obj -> new ValStr<>(obj, obj.getCanonicalPath().toString());
			default -> val;
		};
		super.setEditorValue(editor, param, v);
	}
}
