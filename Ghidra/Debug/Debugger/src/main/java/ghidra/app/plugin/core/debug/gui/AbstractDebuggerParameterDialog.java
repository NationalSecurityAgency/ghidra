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
package ghidra.app.plugin.core.debug.gui;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.beans.*;
import java.io.File;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualLinkedHashBidiMap;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.text.StringEscapeUtils;

import docking.DialogComponentProvider;
import docking.options.editor.FileChooserEditor;
import docking.widgets.button.BrowseButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.core.debug.utils.MiscellaneousUtils;
import ghidra.debug.api.ValStr;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.PathIsDir;
import ghidra.framework.plugintool.AutoConfigState.PathIsFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.layout.PairLayout;

public abstract class AbstractDebuggerParameterDialog<P> extends DialogComponentProvider
		implements PropertyChangeListener {
	static final String KEY_MEMORIZED_ARGUMENTS = "memorizedArguments";

	public static class BigIntEditor extends PropertyEditorSupport {
		String asText = "";

		@Override
		public String getJavaInitializationString() {
			Object value = getValue();
			return value == null
					? "null"
					: "new BigInteger(\"%s\")".formatted(value);
		}

		@Override
		public void setAsText(String text) throws IllegalArgumentException {
			/**
			 * Set asText first, since setValue will fire change listener. It will call getAsText().
			 */
			asText = text;
			setValueNoAsText(text == null
					? null
					: NumericUtilities.decodeBigInteger(text));
		}

		public void setValueNoAsText(Object value) {
			super.setValue(value);
		}

		@Override
		public void setValue(Object value) {
			super.setValue(value);
			asText = value == null ? "" : value.toString();
		}

		@Override
		public String getAsText() {
			return asText;
		}
	}

	public static class FileChooserPanel extends JPanel {
		private final static int NUMBER_OF_COLUMNS = 20;

		private final JTextField textField = new JTextField(NUMBER_OF_COLUMNS);
		private final JButton browseButton = new BrowseButton();
		private final Runnable propertyChange;

		private GhidraFileChooser fileChooser; // lazy

		public FileChooserPanel(Runnable propertyChange) {
			this.propertyChange = propertyChange;

			setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
			add(textField);
			add(Box.createHorizontalStrut(5));
			add(browseButton);
			setBorder(BorderFactory.createEmptyBorder());

			textField.addActionListener(e -> propertyChange.run());
			textField.getDocument().addDocumentListener(new DocumentListener() {
				@Override
				public void removeUpdate(DocumentEvent e) {
					propertyChange.run();
				}

				@Override
				public void insertUpdate(DocumentEvent e) {
					propertyChange.run();
				}

				@Override
				public void changedUpdate(DocumentEvent e) {
					propertyChange.run();
				}
			});

			browseButton.addActionListener(e -> displayFileChooser());
		}

		public void setValue(File file) {
			textField.setText(file == null ? "" : file.getAbsolutePath());
		}

		private void displayFileChooser() {
			if (fileChooser == null) {
				fileChooser = createFileChooser();
			}

			String path = textField.getText().trim();
			if (!path.isEmpty()) {
				File f = new File(path);
				if (f.isDirectory()) {
					fileChooser.setCurrentDirectory(f);
				}
				else {
					File pf = f.getParentFile();
					if (pf != null && pf.isDirectory()) {
						fileChooser.setSelectedFile(f);
					}
				}
			}

			File chosen = fileChooser.getSelectedFile(true);
			if (chosen != null) {
				textField.setText(chosen.getAbsolutePath());
				propertyChange.run();
			}
		}

		protected String getTitle() {
			return "Choose Path";
		}

		protected GhidraFileChooserMode getSelectionMode() {
			return GhidraFileChooserMode.FILES_AND_DIRECTORIES;
		}

		private GhidraFileChooser createFileChooser() {
			GhidraFileChooser chooser = new GhidraFileChooser(browseButton);
			chooser.setTitle(getTitle());
			chooser.setApproveButtonText(getTitle());
			chooser.setFileSelectionMode(getSelectionMode());
			// No way for script to specify filter....

			return chooser;
		}
	}

	/**
	 * Compared to {@link FileChooserEditor}, this does not require the user to enter a full path.
	 * Nor will it resolve file names against the working directory. It's just a text box with a
	 * file browser assist.
	 */
	public static class PathEditor extends PropertyEditorSupport {
		private final FileChooserPanel panel = newChooserPanel();

		protected FileChooserPanel newChooserPanel() {
			return new FileChooserPanel(this::firePropertyChange);
		}

		@Override
		public String getAsText() {
			return panel.textField.getText().trim();
		}

		@Override
		public Object getValue() {
			String text = panel.textField.getText().trim();
			if (text.isEmpty()) {
				return null;
			}
			return Paths.get(text);
		}

		@Override
		public void setAsText(String text) throws IllegalArgumentException {
			if (text == null || text.isBlank()) {
				panel.textField.setText("");
			}
			else {
				panel.textField.setText(text);
			}
		}

		@Override
		public void setValue(Object value) {
			if (value == null) {
				panel.textField.setText("");
			}
			else if (value instanceof String s) {
				panel.textField.setText(s);
			}
			else if (value instanceof Path p) {
				panel.textField.setText(p.toString());
			}
			else {
				throw new IllegalArgumentException("value=" + value);
			}
		}

		@Override
		public boolean supportsCustomEditor() {
			return true;
		}

		@Override
		public Component getCustomEditor() {
			return panel;
		}
	}

	public static class PathIsDirEditor extends PathEditor {
		@Override
		protected FileChooserPanel newChooserPanel() {
			return new FileChooserPanel(this::firePropertyChange) {
				@Override
				protected String getTitle() {
					return "Choose Directory";
				}

				@Override
				protected GhidraFileChooserMode getSelectionMode() {
					return GhidraFileChooserMode.DIRECTORIES_ONLY;
				}
			};
		}

		@Override
		public Object getValue() {
			Object value = super.getValue();
			if (value == null) {
				return null;
			}
			if (value instanceof Path p) {
				return new PathIsDir(p);
			}
			throw new AssertionError();
		}

		@Override
		public void setValue(Object value) {
			if (value instanceof PathIsDir dir) {
				super.setValue(dir.path());
			}
			else {
				super.setValue(value);
			}
		}
	}

	public static class PathIsFileEditor extends PathEditor {
		@Override
		protected FileChooserPanel newChooserPanel() {
			return new FileChooserPanel(this::firePropertyChange) {
				@Override
				protected String getTitle() {
					return "Choose File";
				}

				@Override
				protected GhidraFileChooserMode getSelectionMode() {
					return GhidraFileChooserMode.FILES_ONLY;
				}
			};
		}

		@Override
		public Object getValue() {
			Object value = super.getValue();
			if (value == null) {
				return null;
			}
			if (value instanceof Path p) {
				return new PathIsFile(p);
			}
			throw new AssertionError();
		}

		@Override
		public void setValue(Object value) {
			if (value instanceof PathIsFile file) {
				super.setValue(file.path());
			}
			else {
				super.setValue(value);
			}
		}
	}

	static {
		PropertyEditorManager.registerEditor(BigInteger.class, BigIntEditor.class);
		PropertyEditorManager.registerEditor(Path.class, PathEditor.class);
		PropertyEditorManager.registerEditor(PathIsDir.class, PathIsDirEditor.class);
		PropertyEditorManager.registerEditor(PathIsFile.class, PathIsFileEditor.class);
	}

	static class ChoicesPropertyEditor implements PropertyEditor {
		private final List<?> choices;
		private final String[] tags;

		private final List<PropertyChangeListener> listeners = new ArrayList<>();

		private Object value;

		public ChoicesPropertyEditor(Collection<?> choices) {
			this.choices = choices.stream().distinct().toList();
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

	protected record NameTypePair(String name, Class<?> type) {
		public static NameTypePair fromString(String name) throws ClassNotFoundException {
			String[] parts = name.split(",", 2);
			if (parts.length != 2) {
				// This appears to be a bad assumption - empty fields results in solitary labels
				return new NameTypePair(parts[0], String.class);
				//throw new IllegalArgumentException("Could not parse name,type");
			}
			return new NameTypePair(parts[0], Class.forName(parts[1]));
		}

		public final String encodeString() {
			return name + "," + type.getName();
		}
	}

	private final BidiMap<P, PropertyEditor> paramEditors = new DualLinkedHashBidiMap<>();

	private JPanel panel;
	private JLabel descriptionLabel;
	private JPanel pairPanel;
	private PairLayout layout;

	protected JButton invokeButton;
	protected JButton resetButton;

	private final PluginTool tool;
	// package access for testing
	Map<String, P> parameters;

	private Map<String, ValStr<?>> defaults = Map.of();
	// TODO: Not sure this is the best keying, but I think it works.
	private Map<NameTypePair, ValStr<?>> memorized = new HashMap<>();
	private Map<String, ValStr<?>> arguments;

	public AbstractDebuggerParameterDialog(PluginTool tool, String title, String buttonText,
			Icon buttonIcon) {
		super(title, true, true, true, false);
		this.tool = tool;

		populateComponents(buttonText, buttonIcon);
		setRememberSize(false);
	}

	protected abstract String parameterName(P parameter);

	protected abstract Class<?> parameterType(P parameter);

	protected NameTypePair parameterNameAndType(P parameter) {
		return new NameTypePair(parameterName(parameter), parameterType(parameter));
	}

	protected abstract String parameterLabel(P parameter);

	protected abstract String parameterToolTip(P parameter);

	protected abstract ValStr<?> parameterDefault(P parameter);

	protected abstract Collection<?> parameterChoices(P parameter);

	protected abstract Map<String, ValStr<?>> validateArguments(Map<String, P> parameters,
			Map<String, ValStr<?>> arguments);

	protected abstract void parameterSaveValue(P parameter, SaveState state, String key,
			ValStr<?> value);

	protected abstract ValStr<?> parameterLoadValue(P parameter, SaveState state, String key);

	protected ValStr<?> computeInitialValue(P parameter) {
		ValStr<?> val = memorized.computeIfAbsent(parameterNameAndType(parameter),
			ntp -> defaults.get(parameterName(parameter)));
		return val;
	}

	/**
	 * Prompt the user for the given arguments, all at once
	 * 
	 * <p>
	 * This displays a single dialog with each option listed. The parameter map contains the
	 * description of each parameter to be displayed. The {@code initial} values are the values to
	 * pre-populate the options with, e.g., because they are saved from a previous session, or
	 * because they are the suggested values. If the user clicks the "Reset" button, the values are
	 * revered to the defaults given in each parameter's description, unless that value is
	 * overridden in {@code defaults}. This may be appropriate if a value is suggested for a
	 * (perhaps required) option that otherwise has no default.
	 * 
	 * @param parameterMap the map of parameters, keyed by {@link #parameterName(Object)}. This map
	 *            may be ordered to control the order of options displayed.
	 * @param initial the initial values of the options. If a key is not provided, the initial value
	 *            is its default value. Extraneous keys are ignored.
	 * @param defaults the default values to use upon reset. If a key is not provided, the default
	 *            is taken from the parameter description. Extraneous keys are ignored.
	 * @return the arguments provided by the user
	 */
	public Map<String, ValStr<?>> promptArguments(Map<String, P> parameterMap,
			Map<String, ValStr<?>> initial, Map<String, ValStr<?>> defaults) {
		setDefaults(defaults);
		setParameters(parameterMap);
		setMemorizedArguments(initial);
		populateValues(initial);
		tool.showDialog(this);

		return getArguments();
	}

	protected void setParameters(Map<String, P> parameterMap) {
		this.parameters = parameterMap;
		for (P param : parameterMap.values()) {
			if (!defaults.containsKey(parameterName(param))) {
				defaults.put(parameterName(param), parameterDefault(param));
			}
		}
		populateOptions();
	}

	protected void setMemorizedArguments(Map<String, ValStr<?>> initial) {
		for (P param : parameters.values()) {
			ValStr<?> val = initial.get(parameterName(param));
			if (val != null) {
				setMemorizedArgument(param, val);
			}
		}
	}

	protected void setDefaults(Map<String, ValStr<?>> defaults) {
		this.defaults = new HashMap<>(defaults);
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

	void invoke(ActionEvent evt) {
		try {
			this.arguments = validateArguments(parameters, collectArguments());
			close();
		}
		catch (IllegalStateException e) {
			setStatusText(e.getMessage(), MessageType.ERROR, true);
		}
	}

	void reset(ActionEvent evt) {
		this.arguments = null;
		populateValues(defaults);
	}

	protected PropertyEditor createEditor(P parameter) {
		Collection<?> choices = parameterChoices(parameter);
		if (!choices.isEmpty()) {
			return new ChoicesPropertyEditor(choices);
		}
		Class<?> type = parameterType(parameter);
		PropertyEditor editor = PropertyEditorManager.findEditor(type);
		if (editor != null) {
			return editor;
		}
		Msg.warn(this, "No editor for " + type + "? Trying String instead");
		editor = PropertyEditorManager.findEditor(String.class);
		return editor;
	}

	// test access
	PropertyEditor getEditor(P parameter) {
		return paramEditors.get(parameter);
	}

	protected void setEditorValue(PropertyEditor editor, P param, ValStr<?> val) {
		switch (val.val()) {
			case null -> {
				if (parameterType(param) == String.class) {
					editor.setValue(val.str());
				}
			}
			case BigInteger bi -> editor.setAsText(val.str());
			default -> editor.setValue(val.val());
		}
	}

	void populateOptions() {
		pairPanel.removeAll();
		paramEditors.clear();
		for (P param : parameters.values()) {
			JLabel label = new JLabel(parameterLabel(param));
			label.setToolTipText(parameterToolTip(param));
			pairPanel.add(label);

			PropertyEditor editor = createEditor(param);
			ValStr<?> val = computeInitialValue(param);
			setEditorValue(editor, param, val);
			editor.addPropertyChangeListener(this);
			pairPanel.add(MiscellaneousUtils.getEditorComponent(editor));
			paramEditors.put(param, editor);
		}
	}

	void populateValues(Map<String, ValStr<?>> values) {
		for (Map.Entry<String, ValStr<?>> ent : values.entrySet()) {
			P param = parameters.get(ent.getKey());
			if (param == null) {
				continue;
			}
			PropertyEditor editor = paramEditors.get(param);
			setEditorValue(editor, param, ent.getValue());
		}
	}

	protected Map<String, ValStr<?>> collectArguments() {
		Map<String, ValStr<?>> map = new LinkedHashMap<>();
		Set<String> invalid = new LinkedHashSet<>();
		for (Entry<P, PropertyEditor> ent : paramEditors.entrySet()) {
			P param = ent.getKey();
			PropertyEditor editor = ent.getValue();
			ValStr<?> val = memorized.get(parameterNameAndType(param));
			if (!Objects.equals(editor.getAsText(), val.str())) {
				invalid.add(parameterLabel(param));
			}
			if (val != null) {
				map.put(parameterName(param), val);
			}
		}
		if (!invalid.isEmpty()) {
			throw new IllegalStateException("Invalid value for " + invalid);
		}
		return map;
	}

	public Map<String, ValStr<?>> getArguments() {
		return arguments;
	}

	void setMemorizedArgument(P parameter, ValStr<?> value) {
		if (value == null) {
			return;
		}
		memorized.put(parameterNameAndType(parameter), value);
		PropertyEditor editor = paramEditors.get(parameter);
		// Editors may not be populated yet
		if (editor != null) {
			setEditorValue(editor, parameter, value);
		}
	}

	public void forgetMemorizedArguments() {
		memorized.clear();
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		PropertyEditor editor = (PropertyEditor) evt.getSource();
		P param = paramEditors.getKey(editor);
		memorized.put(parameterNameAndType(param),
			new ValStr<>(editor.getValue(), editor.getAsText()));
	}

	public void writeConfigState(SaveState saveState) {
		SaveState subState = new SaveState();
		for (Map.Entry<NameTypePair, ValStr<?>> ent : memorized.entrySet()) {
			NameTypePair ntp = ent.getKey();
			P param = parameters.get(ntp.name());
			if (param == null) {
				continue;
			}
			parameterSaveValue(param, subState, ntp.encodeString(), ent.getValue());
		}
		saveState.putSaveState(KEY_MEMORIZED_ARGUMENTS, subState);
	}

	public void readConfigState(SaveState saveState) {
		/**
		 * TODO: This method is defunct. It is only used by the DebuggerObjectsProvider, which is
		 * now deprecated, but I suspect other providers intend to use this in the same way. If
		 * those providers don't manually load/compute initial and default values at the time of
		 * prompting, then this will need to be fixed. The decode of the values will need to be
		 * delayed until (and repeated every time) parameters are populated.
		 */
		SaveState subState = saveState.getSaveState(KEY_MEMORIZED_ARGUMENTS);
		if (subState == null) {
			return;
		}
		for (String name : subState.getNames()) {
			try {
				NameTypePair ntp = NameTypePair.fromString(name);
				P param = parameters.get(ntp.name());
				if (param == null) {
					continue;
				}
				memorized.put(ntp, parameterLoadValue(param, subState, ntp.encodeString()));
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
