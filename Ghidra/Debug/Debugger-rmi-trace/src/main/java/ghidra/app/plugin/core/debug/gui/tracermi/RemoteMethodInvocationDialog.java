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

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Graphics;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyEditor;
import java.beans.PropertyEditorManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.EmptyBorder;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualLinkedHashBidiMap;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.jdom.Element;

import docking.DialogComponentProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiTarget;
import ghidra.app.plugin.core.debug.utils.MiscellaneousUtils;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.debug.api.tracermi.RemoteParameter;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigStateField;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;

public class RemoteMethodInvocationDialog extends DialogComponentProvider
		implements PropertyChangeListener {
	private static final String KEY_MEMORIZED_ARGUMENTS = "memorizedArguments";

	static class ChoicesPropertyEditor implements PropertyEditor {
		private final List<?> choices;
		private final String[] tags;

		private final List<PropertyChangeListener> listeners = new ArrayList<>();

		private Object value;

		public ChoicesPropertyEditor(Set<?> choices) {
			this.choices = List.copyOf(choices);
			this.tags = choices.stream().map(Objects::toString).toArray(String[]::new);
		}

		@Override
		public void setValue(Object value) {
			if (Objects.equals(value, this.value)) {
				return;
			}
			if (!choices.contains(value)) {
				throw new IllegalArgumentException("Unsupported value: " + value);
			}
			Object oldValue;
			List<PropertyChangeListener> listeners;
			synchronized (this.listeners) {
				oldValue = this.value;
				this.value = value;
				if (this.listeners.isEmpty()) {
					return;
				}
				listeners = List.copyOf(this.listeners);
			}
			PropertyChangeEvent evt = new PropertyChangeEvent(this, null, oldValue, value);
			for (PropertyChangeListener l : listeners) {
				l.propertyChange(evt);
			}
		}

		@Override
		public Object getValue() {
			return value;
		}

		@Override
		public boolean isPaintable() {
			return false;
		}

		@Override
		public void paintValue(Graphics gfx, Rectangle box) {
			// Not paintable
		}

		@Override
		public String getJavaInitializationString() {
			if (value == null) {
				return "null";
			}
			if (value instanceof String str) {
				return "\"" + StringEscapeUtils.escapeJava(str) + "\"";
			}
			return Objects.toString(value);
		}

		@Override
		public String getAsText() {
			return Objects.toString(value);
		}

		@Override
		public void setAsText(String text) throws IllegalArgumentException {
			int index = ArrayUtils.indexOf(tags, text);
			if (index < 0) {
				throw new IllegalArgumentException("Unsupported value: " + text);
			}
			setValue(choices.get(index));
		}

		@Override
		public String[] getTags() {
			return tags.clone();
		}

		@Override
		public Component getCustomEditor() {
			return null;
		}

		@Override
		public boolean supportsCustomEditor() {
			return false;
		}

		@Override
		public void addPropertyChangeListener(PropertyChangeListener listener) {
			synchronized (listeners) {
				listeners.add(listener);
			}
		}

		@Override
		public void removePropertyChangeListener(PropertyChangeListener listener) {
			synchronized (listeners) {
				listeners.remove(listener);
			}
		}
	}

	record NameTypePair(String name, Class<?> type) {
		public static NameTypePair fromParameter(SchemaContext ctx, RemoteParameter parameter) {
			return new NameTypePair(parameter.name(), ctx.getSchema(parameter.type()).getType());
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
	}

	private final BidiMap<RemoteParameter, PropertyEditor> paramEditors =
		new DualLinkedHashBidiMap<>();

	private JPanel panel;
	private JLabel descriptionLabel;
	private JPanel pairPanel;
	private PairLayout layout;

	protected JButton invokeButton;
	protected JButton resetButton;

	private final PluginTool tool;
	private SchemaContext ctx;
	private Map<String, RemoteParameter> parameters;
	private Map<String, Object> defaults;

	// TODO: Not sure this is the best keying, but I think it works.
	private Map<NameTypePair, Object> memorized = new HashMap<>();
	private Map<String, Object> arguments;

	public RemoteMethodInvocationDialog(PluginTool tool, String title, String buttonText,
			Icon buttonIcon) {
		super(title, true, true, true, false);
		this.tool = tool;

		populateComponents(buttonText, buttonIcon);
		setRememberSize(false);
	}

	protected Object computeMemorizedValue(RemoteParameter parameter) {
		return memorized.computeIfAbsent(NameTypePair.fromParameter(ctx, parameter),
			ntp -> parameter.getDefaultValue());
	}

	public Map<String, Object> promptArguments(SchemaContext ctx,
			Map<String, RemoteParameter> parameterMap, Map<String, Object> defaults) {
		setParameters(ctx, parameterMap);
		setDefaults(defaults);
		tool.showDialog(this);

		return getArguments();
	}

	public void setParameters(SchemaContext ctx, Map<String, RemoteParameter> parameterMap) {
		this.ctx = ctx;
		this.parameters = parameterMap;
		populateOptions();
	}

	public void setDefaults(Map<String, Object> defaults) {
		this.defaults = defaults;
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

		descriptionLabel = new JLabel();
		descriptionLabel.setMaximumSize(new Dimension(300, 100));
		panel.add(descriptionLabel, BorderLayout.NORTH);

		addWorkPanel(panel);

		invokeButton = new JButton(buttonText, buttonIcon);
		addButton(invokeButton);
		resetButton = new JButton("Reset", DebuggerResources.ICON_REFRESH);
		addButton(resetButton);
		addCancelButton();

		invokeButton.addActionListener(this::invoke);
		resetButton.addActionListener(this::reset);
	}

	@Override
	protected void cancelCallback() {
		this.arguments = null;
		close();
	}

	protected void invoke(ActionEvent evt) {
		this.arguments = collectArguments();
		close();
	}

	private void reset(ActionEvent evt) {
		this.arguments = new HashMap<>();
		for (RemoteParameter param : parameters.values()) {
			if (defaults.containsKey(param.name())) {
				arguments.put(param.name(), defaults.get(param.name()));
			}
			else {
				arguments.put(param.name(), param.getDefaultValue());
			}
		}
		populateValues();
	}

	protected PropertyEditor createEditor(RemoteParameter param) {
		Class<?> type = ctx.getSchema(param.type()).getType();
		PropertyEditor editor = PropertyEditorManager.findEditor(type);
		if (editor != null) {
			return editor;
		}
		Msg.warn(this, "No editor for " + type + "? Trying String instead");
		return PropertyEditorManager.findEditor(String.class);
	}

	void populateOptions() {
		pairPanel.removeAll();
		paramEditors.clear();
		for (RemoteParameter param : parameters.values()) {
			String text = param.display().equals("") ? param.name() : param.display();
			JLabel label = new JLabel(text);
			label.setToolTipText(param.description());
			pairPanel.add(label);

			PropertyEditor editor = createEditor(param);
			Object val = computeMemorizedValue(param);
			if (val == null || val.equals(TraceRmiTarget.Missing.MISSING)) {
				editor.setValue("");
			} else {
				editor.setValue(val);
			}
			editor.addPropertyChangeListener(this);
			pairPanel.add(MiscellaneousUtils.getEditorComponent(editor));
			paramEditors.put(param, editor);
		}
	}

	void populateValues() {
		for (Map.Entry<String, Object> ent : arguments.entrySet()) {
			RemoteParameter param = parameters.get(ent.getKey());
			if (param == null) {
				Msg.warn(this, "No parameter for argument: " + ent);
				continue;
			}
			PropertyEditor editor = paramEditors.get(param);
			editor.setValue(ent.getValue());
		}
	}

	protected Map<String, Object> collectArguments() {
		Map<String, Object> map = new LinkedHashMap<>();
		for (RemoteParameter param : paramEditors.keySet()) {
			Object val = memorized.get(NameTypePair.fromParameter(ctx, param));
			if (val != null) {
				map.put(param.name(), val);
			}
		}
		return map;
	}

	public Map<String, Object> getArguments() {
		return arguments;
	}

	public <T> void setMemorizedArgument(String name, Class<T> type, T value) {
		if (value == null) {
			return;
		}
		memorized.put(new NameTypePair(name, type), value);
	}

	public <T> T getMemorizedArgument(String name, Class<T> type) {
		return type.cast(memorized.get(new NameTypePair(name, type)));
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		PropertyEditor editor = (PropertyEditor) evt.getSource();
		RemoteParameter param = paramEditors.getKey(editor);
		memorized.put(NameTypePair.fromParameter(ctx, param), editor.getValue());
	}

	public void writeConfigState(SaveState saveState) {
		SaveState subState = new SaveState();
		for (Map.Entry<NameTypePair, Object> ent : memorized.entrySet()) {
			NameTypePair ntp = ent.getKey();
			ConfigStateField.putState(subState, ntp.type().asSubclass(Object.class), ntp.name(),
				ent.getValue());
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
				memorized.put(ntp, ConfigStateField.getState(subState, ntp.type(), ntp.name()));
			}
			catch (Exception e) {
				Msg.error(this, "Error restoring memorized parameter " + name, e);
			}
		}
	}

	public void setDescription(String htmlDescription) {
		if (htmlDescription == null) {
			descriptionLabel.setBorder(BorderFactory.createEmptyBorder());
			descriptionLabel.setText("");
		}
		else {
			descriptionLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
			descriptionLabel.setText(htmlDescription);
		}
	}
}
