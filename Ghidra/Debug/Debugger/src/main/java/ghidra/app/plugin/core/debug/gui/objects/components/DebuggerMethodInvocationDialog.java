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

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.beans.*;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualLinkedHashBidiMap;
import org.apache.commons.lang3.tuple.MutablePair;
import org.jdom.Element;

import docking.DialogComponentProvider;
import ghidra.app.plugin.core.debug.utils.MiscellaneousUtils;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigStateField;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;

public class DebuggerMethodInvocationDialog extends DialogComponentProvider
		implements PropertyChangeListener {
	private static final String KEY_MEMORIZED_ARGUMENTS = "memorizedArguments";

	final static class NameTypePair extends MutablePair<String, Class<?>> {

		public static NameTypePair fromParameter(ParameterDescription<?> parameter) {
			return new NameTypePair(parameter.name, parameter.type);
		}

		public static NameTypePair fromString(String name) throws ClassNotFoundException {
			String[] parts = name.split(",", 2);
			if (parts.length != 2) {
				// This appears to be a bad assumption - empty fields results in solitary labels
				return new NameTypePair(parts[0], String.class);
				//throw new IllegalArgumentException("Could not parse name,type");
			}
			return new NameTypePair(parts[0], Class.forName(parts[1]));
		}

		public NameTypePair(String name, Class<?> type) {
			super(name, type);
		}

		@Override
		public String toString() {
			return getName() + "," + getType().getName();
		}

		@Override
		public Class<?> setValue(Class<?> value) {
			throw new UnsupportedOperationException();
		}

		public String getName() {
			return getLeft();
		}

		public Class<?> getType() {
			return getRight();
		}
	}

	private final BidiMap<ParameterDescription<?>, PropertyEditor> paramEditors =
		new DualLinkedHashBidiMap<>();

	private JPanel panel;
	private JPanel pairPanel;
	private PairLayout layout;

	protected JButton invokeButton;

	private final PluginTool tool;
	private Map<String, ParameterDescription<?>> parameters;

	// TODO: Not sure this is the best keying, but I think it works.
	private Map<NameTypePair, Object> memorized = new HashMap<>();
	private Map<String, ?> arguments;

	public DebuggerMethodInvocationDialog(PluginTool tool, String title, String buttonText,
			Icon buttonIcon) {
		super(title, true, false, true, false);
		this.tool = tool;

		populateComponents(buttonText, buttonIcon);
		setRememberSize(false);
	}

	protected Object computeMemorizedValue(ParameterDescription<?> parameter) {
		return memorized.computeIfAbsent(NameTypePair.fromParameter(parameter),
			ntp -> parameter.defaultValue);
	}

	public Map<String, ?> promptArguments(Map<String, ParameterDescription<?>> parameterMap) {
		setParameters(parameterMap);
		tool.showDialog(this);

		return getArguments();
	}

	public void setParameters(Map<String, ParameterDescription<?>> parameterMap) {
		this.parameters = parameterMap;
		populateOptions();
	}

	private void populateComponents(String buttonText, Icon buttonIcon) {
		panel = new JPanel(new BorderLayout());
		panel.setBorder(new EmptyBorder(10, 10, 10, 10));

		layout = new PairLayout(5, 5);
		pairPanel = new JPanel(layout);

		JPanel centering = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JScrollPane scrolling = new JScrollPane(centering, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
			JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		//scrolling.setPreferredSize(new Dimension(100, 130));
		panel.add(scrolling, BorderLayout.CENTER);
		centering.add(pairPanel);

		addWorkPanel(panel);

		invokeButton = new JButton(buttonText, buttonIcon);
		addButton(invokeButton);
		addCancelButton();

		invokeButton.addActionListener(this::invoke);
	}

	@Override
	protected void cancelCallback() {
		this.arguments = null;
		close();
	}

	private void invoke(ActionEvent evt) {
		this.arguments = TargetMethod.validateArguments(parameters, collectArguments(), false);
		close();
	}

	void populateOptions() {
		pairPanel.removeAll();
		//layout.setRows(Math.max(1, parameters.size()));
		paramEditors.clear();
		for (ParameterDescription<?> param : parameters.values()) {
			JLabel label = new JLabel(param.display);
			label.setToolTipText(param.description);
			pairPanel.add(label);

			Class<?> type = param.type;
			PropertyEditor editor = PropertyEditorManager.findEditor(type);
			if (editor == null) {
				Msg.warn(this, "No editor for " + type + "? Trying String instead");
				editor = PropertyEditorManager.findEditor(String.class);
			}
			editor.setValue(computeMemorizedValue(param));
			editor.addPropertyChangeListener(this);
			pairPanel.add(MiscellaneousUtils.getEditorComponent(editor));
			// TODO: How to handle parameter with choices?
			paramEditors.put(param, editor);
		}
	}

	protected Map<String, ?> collectArguments() {
		return paramEditors.keySet()
				.stream()
				.collect(Collectors.toMap(param -> param.name,
					param -> memorized.get(NameTypePair.fromParameter(param))));
	}

	public Map<String, ?> getArguments() {
		return arguments;
	}

	public <T> void setMemorizedArgument(String name, Class<T> type, T value) {
		memorized.put(new NameTypePair(name, type), value);
	}

	public <T> T getMemorizedArgument(String name, Class<T> type) {
		return type.cast(memorized.get(new NameTypePair(name, type)));
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		PropertyEditor editor = (PropertyEditor) evt.getSource();
		ParameterDescription<?> param = paramEditors.getKey(editor);
		memorized.put(NameTypePair.fromParameter(param), editor.getValue());
	}

	public void writeConfigState(SaveState saveState) {
		SaveState subState = new SaveState();
		for (Map.Entry<NameTypePair, Object> ent : memorized.entrySet()) {
			NameTypePair ntp = ent.getKey();
			ConfigStateField.putState(subState, ntp.getType().asSubclass(Object.class),
				ntp.getName(), ent.getValue());
		}
		saveState.putXmlElement(KEY_MEMORIZED_ARGUMENTS, subState.saveToXml());
	}

	public void readConfigState(SaveState saveState) {
		Element element = saveState.getXmlElement(KEY_MEMORIZED_ARGUMENTS);
		if (element == null) {
			return;
		}
		SaveState subState = new SaveState(element);
		for (String name : subState.getNames()) {
			try {
				NameTypePair ntp = NameTypePair.fromString(name);
				memorized.put(ntp,
					ConfigStateField.getState(subState, ntp.getType(), ntp.getName()));
			}
			catch (Exception e) {
				Msg.error(this, "Error restoring memorized parameter " + name, e);
			}
		}
	}
}
