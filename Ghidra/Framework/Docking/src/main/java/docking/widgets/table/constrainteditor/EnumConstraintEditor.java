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
package docking.widgets.table.constrainteditor;

import java.awt.*;
import java.lang.reflect.Method;
import java.util.*;

import javax.swing.*;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDHtmlLabel;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.EnumColumnConstraint;

/**
 * A constraint editor for enumerated-type values;
*/
public class EnumConstraintEditor<T extends Enum<T>> extends AbstractColumnConstraintEditor<T> {

	private Set<T> allValues;
	private Set<T> selectedValues;

	private Map<T, JCheckBox> enumCheckboxMap = new HashMap<>();

	public static final String CHECKBOX_NAME_PREFIX = "enumCheckbox_";

	private JLabel infoLabel;

	/**
	 * Constructor.
	 *
	 * @param constraint Enum-type constraint for which this component is an editor.
	 */
	public EnumConstraintEditor(EnumColumnConstraint<T> constraint) {
		super(constraint);
		allValues = EnumSet.allOf(constraint.getEnumClass());
		selectedValues = new HashSet<>();
	}

	@Override
	protected Component buildInlineEditorComponent() {

		JPanel panel = new JPanel(new GridLayout(0, 2, 5, 5));
		panel.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 10));

		for (T t : allValues) {
			GCheckBox jCheckBox = new GCheckBox(getElementDisplayName(t));

			enumCheckboxMap.put(t, jCheckBox);

			jCheckBox.setName(String.format("%s%03d", CHECKBOX_NAME_PREFIX, t.ordinal()));
			jCheckBox.addItemListener(e -> {
				if (jCheckBox.isSelected()) {
					selectedValues.add(t);
				}
				else {
					selectedValues.remove(t);
				}
				valueChanged();
			});
			panel.add(jCheckBox);
		}

		JPanel outerPanel = new JPanel(new BorderLayout());
		outerPanel.add(panel, BorderLayout.CENTER);

		infoLabel = new GDHtmlLabel("");
		infoLabel.setForeground(Color.GRAY);
		infoLabel.setHorizontalAlignment(SwingConstants.CENTER);
		outerPanel.add(infoLabel, BorderLayout.SOUTH);

		return outerPanel;
	}

	/**
	 * Resolves and returns a more friendly display name for a given Enum value.
	 * <p>
	 * Several Ghidra enumerated types provide functions for retrieving formatted
	 * name for a value; this attempts to locate one such function within the Enum class.
	 * <p>
	 * This searches the enum class for a zero-argument, String-returning method called
	 * <code>getName()</code>, <code>getDisplayName()</code>, or <code>getDisplayString()</code>
	 * before falling back to <code>toString()</code>.
	 *
	 * @return a more user-friendly name for the value
	 */
	public String getElementDisplayName(T value) {
		String displayName = getDisplayNameUsingMethodNamed("getName", value);
		if (displayName != null) {
			return displayName;
		}

		displayName = getDisplayNameUsingMethodNamed("getDisplayName", value);
		if (displayName != null) {
			return displayName;
		}

		displayName = getDisplayNameUsingMethodNamed("getDisplayString", value);
		if (displayName != null) {
			return displayName;
		}
		return value.toString();
	}

	private String getDisplayNameUsingMethodNamed(String methodName, T value) {
		try {
			Method method = getConstraint().getEnumClass().getMethod(methodName);
			if (method.getReturnType() != String.class) {
				return null;
			}
			if (method.getParameterCount() != 0) {
				return null;
			}
			return (String) method.invoke(value);
		}
		catch (Exception e) {
			return null;
		}
	}

	@Override
	protected ColumnConstraint<T> getValueFromComponent() {
		Set<T> values = new HashSet<>(selectedValues);
		return new EnumColumnConstraint<>(getConstraint().getEnumClass(), values);
	}

	private EnumColumnConstraint<T> getConstraint() {
		return (EnumColumnConstraint<T>) currentConstraint;
	}

	@Override
	protected void updateEditorComponent() {
		selectedValues = new HashSet<>(getConstraint().getSelectedValues());

		for (Map.Entry<T, JCheckBox> entry : enumCheckboxMap.entrySet()) {
			boolean selected = selectedValues.contains(entry.getKey());
			entry.getValue().setSelected(selected);
		}
	}

	@Override
	public void reset() {
		setValue(
			new EnumColumnConstraint<>(getConstraint().getEnumClass(), Collections.emptySet()));
	}

	@Override
	protected boolean checkEditorValueValidity() {
		return !selectedValues.isEmpty();
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		String status = formatStatus(isValid ? "&nbsp;" : "Please select at least one value", true);
		infoLabel.setText(status);
	}

	@Override
	public String getErrorMessage() {
		return "Please select one or more elements";
	}

}
