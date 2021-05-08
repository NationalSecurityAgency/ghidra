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
package docking.widgets.model;

import java.awt.Component;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

import javax.swing.*;

import com.google.common.collect.BoundType;
import com.google.common.collect.Range;

public class GLifespanField extends JPanel {
	private static final String NEG_INF = "-\u221e";
	private static final String POS_INF = "+\u221e";

	private final JLabel labelLower = new JLabel("[");
	private final JComboBox<String> fieldMin = new JComboBox<>();
	private final JComboBox<String> fieldMax = new JComboBox<>();
	private final JLabel labelUpper = new JLabel("]");

	private final DefaultComboBoxModel<String> modelMin = new DefaultComboBoxModel<>();
	private final DefaultComboBoxModel<String> modelMax = new DefaultComboBoxModel<>();

	public GLifespanField() {
		setLayout(new BoxLayout(this, BoxLayout.X_AXIS));

		add(labelLower);
		add(fieldMin);
		add(new JLabel("\u2025"));
		add(fieldMax);
		add(labelUpper);

		modelMin.addElement(NEG_INF);
		modelMax.addElement(POS_INF);

		fieldMin.setEditable(true);
		fieldMin.setModel(modelMin);
		fieldMax.setEditable(true);
		fieldMax.setModel(modelMax);

		fieldMin.getEditor().getEditorComponent().addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				minFocusLost(e);
				checkDispatchFocus(e);
			}
		});
		fieldMax.getEditor().getEditorComponent().addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				maxFocusLost(e);
				checkDispatchFocus(e);
			}
		});
	}

	protected void checkDispatchFocus(FocusEvent e) {
		Component opp = e.getOppositeComponent();
		if (opp == null || !SwingUtilities.isDescendingFrom(opp, this)) {
			dispatchEvent(e);
		}
	}

	protected long parseLong(String text, long defaultVal) {
		try {
			return Long.parseLong(text);
		}
		catch (NumberFormatException e) {
			return defaultVal;
		}
	}

	protected void revalidateMin() {
		String value = (String) fieldMin.getSelectedItem();
		if (NEG_INF.equals(value)) {
			labelLower.setText("(");
		}
		else {
			fieldMin.setSelectedItem(Long.toString(parseLong(value, 0)));
			labelLower.setText("[");
		}
	}

	protected void revalidateMax() {
		String value = (String) fieldMax.getSelectedItem();
		if (POS_INF.equals(value)) {
			labelUpper.setText(")");
		}
		else {
			fieldMax.setSelectedItem(Long.toString(parseLong(value, 0)));
			labelUpper.setText("]");
		}
	}

	protected void adjustMaxToMin() {
		if (unbounded()) {
			return;
		}
		long min = parseLong((String) fieldMin.getSelectedItem(), 0);
		long max = Math.max(min, parseLong((String) fieldMax.getSelectedItem(), min));
		fieldMax.setSelectedItem(Long.toString(max));
	}

	protected boolean unbounded() {
		return NEG_INF.equals(fieldMin.getSelectedItem()) ||
			POS_INF.equals(fieldMax.getSelectedItem());
	}

	protected void adjustMinToMax() {
		if (unbounded()) {
			return;
		}
		long max = parseLong((String) fieldMax.getSelectedItem(), 0);
		long min = Math.min(max, parseLong((String) fieldMin.getSelectedItem(), max));
		fieldMin.setSelectedItem(Long.toString(min));
	}

	protected void minFocusLost(FocusEvent e) {
		revalidateMin();
		adjustMaxToMin();
	}

	protected void maxFocusLost(FocusEvent e) {
		revalidateMax();
		adjustMinToMax();
	}

	public void setLifespan(Range<Long> lifespan) {
		if (lifespan.hasLowerBound() && lifespan.lowerBoundType() == BoundType.OPEN ||
			lifespan.hasUpperBound() && lifespan.upperBoundType() == BoundType.OPEN) {
			throw new IllegalArgumentException("Lifespans must be closed or unbounded");
		}

		if (!lifespan.hasLowerBound()) {
			fieldMin.setSelectedItem(NEG_INF);
		}
		else {
			fieldMin.setSelectedItem(Long.toString(lifespan.lowerEndpoint()));
		}

		if (!lifespan.hasUpperBound()) {
			fieldMax.setSelectedItem(POS_INF);
		}
		else {
			fieldMax.setSelectedItem(Long.toString(lifespan.upperEndpoint()));
		}
	}

	public Range<Long> getLifespan() {
		String min = (String) fieldMin.getSelectedItem();
		String max = (String) fieldMax.getSelectedItem();
		if (NEG_INF.equals(min)) {
			if (POS_INF.equals(max)) {
				return Range.all();
			}
			else {
				return Range.atMost(Long.parseLong(max));
			}
		}
		else {
			if (POS_INF.equals(max)) {
				return Range.atLeast(Long.parseLong(min));
			}
			else {
				return Range.closed(Long.parseLong(min), Long.parseLong(max));
			}
		}
	}

	@Override
	public void setEnabled(boolean enabled) {
		super.setEnabled(enabled);
		fieldMin.setEnabled(enabled);
		fieldMax.setEnabled(enabled);
	}
}
