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
package ghidra.app.plugin.core.datamgr;

import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.program.model.data.DataOrganizationImpl;
import ghidra.util.layout.PairLayout;

public class DataOrganizationPanel extends JPanel {

	JCheckBox charIsSignedCheckbox;
	JTextField charSizeComponent;
	JTextField wcharSizeComponent;
	JTextField shortSizeComponent;
	JTextField integerSizeComponent;
	JTextField longSizeComponent;
	JTextField longLongSizeComponent;
	JTextField floatSizeComponent;
	JTextField doubleSizeComponent;
	JTextField longDoubleSizeComponent;

	JTextField absoluteMaxAlignComponent;
	JTextField machineAlignComponent;
	JTextField defaultAlignComponent;
	JTextField pointerAlignComponent;

	DataOrganizationImpl dataOrganization;

	public DataOrganizationPanel() {
		super(new PairLayout(3, 5));
		setUpAbsoluteMaxAlignment();
		setUpMachineAlignment();
		setUpDefaultAlignment();
		setUpPointerAlignment();
		setUpSignedChar();
		setUpCharSize();
		setUpWideCharSize();
		setUpShortSize();
		setUpIntegerSize();
		setUpLongSize();
		setUpLongLongSize();
		setUpFloatSize();
		setUpDoubleSize();
		setUpLongDoubleSize();

		add(new GLabel(""));
		add(new GLabel(""));
		add(new GLabel("Absolute Max Alignment"));
		add(absoluteMaxAlignComponent);
		add(new GLabel("Machine Alignment"));
		add(machineAlignComponent);
		add(new GLabel("Default Alignment"));
		add(defaultAlignComponent);
		add(new GLabel("Default Pointer Alignment"));
		add(pointerAlignComponent);

		add(new GLabel(""));
		add(new GLabel(""));
		add(new GLabel("Signed-Char:"));
		add(charIsSignedCheckbox);
		add(new GLabel("Char Size"));
		add(charSizeComponent);
		add(new GLabel("Wide-Char Size"));
		add(wcharSizeComponent);
		add(new GLabel("Short Size"));
		add(shortSizeComponent);
		add(new GLabel("Integer Size"));
		add(integerSizeComponent);
		add(new GLabel("Long Size"));
		add(longSizeComponent);
		add(new GLabel("LongLong Size"));
		add(longLongSizeComponent);
		add(new GLabel("Float Size"));
		add(floatSizeComponent);
		add(new GLabel("Double Size"));
		add(doubleSizeComponent);
		add(new GLabel("LongDouble Size"));
		add(longDoubleSizeComponent);
		add(new GLabel(""));
		add(new GLabel(""));
	}

	public void setOrganization(DataOrganizationImpl dataOrganization) {
		this.dataOrganization = dataOrganization;

		int absoluteMaxAlignment = dataOrganization.getAbsoluteMaxAlignment();
		int machineAlignment = dataOrganization.getMachineAlignment();
		int defaultAlignment = dataOrganization.getDefaultAlignment();
		int defaultPointerAlignment = dataOrganization.getDefaultPointerAlignment();

		int charSize = dataOrganization.getCharSize();
		int wcharSize = dataOrganization.getWideCharSize();
		int shortSize = dataOrganization.getShortSize();
		int integerSize = dataOrganization.getIntegerSize();
		int longSize = dataOrganization.getLongSize();
		int longLongSize = dataOrganization.getLongLongSize();
		int floatSize = dataOrganization.getFloatSize();
		int doubleSize = dataOrganization.getDoubleSize();
		int longDoubleSize = dataOrganization.getLongDoubleSize();

		String maxAlignString =
			(absoluteMaxAlignment == 0) ? "none" : Integer.toString(absoluteMaxAlignment);
		absoluteMaxAlignComponent.setText(maxAlignString);
		machineAlignComponent.setText(Integer.toString(machineAlignment));
		defaultAlignComponent.setText(Integer.toString(defaultAlignment));
		pointerAlignComponent.setText(Integer.toString(defaultPointerAlignment));

		charSizeComponent.setText(Integer.toString(charSize));
		wcharSizeComponent.setText(Integer.toString(wcharSize));
		shortSizeComponent.setText(Integer.toString(shortSize));
		integerSizeComponent.setText(Integer.toString(integerSize));
		longSizeComponent.setText(Integer.toString(longSize));
		longLongSizeComponent.setText(Integer.toString(longLongSize));
		floatSizeComponent.setText(Integer.toString(floatSize));
		doubleSizeComponent.setText(Integer.toString(doubleSize));
		longDoubleSizeComponent.setText(Integer.toString(longDoubleSize));
	}

	private void setUpSignedChar() {
		charIsSignedCheckbox = new GCheckBox();
		charIsSignedCheckbox.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				updateSignedChar();
			}
		});
	}

	private void setUpCharSize() {
		charSizeComponent = new JTextField(3);
		charSizeComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedCharSize();
			}
		});
		charSizeComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedCharSize();
			}
		});
	}

	private void setUpWideCharSize() {
		wcharSizeComponent = new JTextField(3);
		wcharSizeComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedWideCharSize();
			}
		});
		wcharSizeComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedWideCharSize();
			}
		});
	}

	private void setUpShortSize() {
		shortSizeComponent = new JTextField(3);
		shortSizeComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedShortSize();
			}
		});
		shortSizeComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedShortSize();
			}
		});
	}

	private void setUpIntegerSize() {
		integerSizeComponent = new JTextField(3);
		integerSizeComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedIntegerSize();
			}
		});
		integerSizeComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedIntegerSize();
			}
		});
	}

	private void setUpLongSize() {
		longSizeComponent = new JTextField(3);
		longSizeComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedLongSize();
			}
		});
		longSizeComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedLongSize();
			}
		});
	}

	private void setUpLongLongSize() {
		longLongSizeComponent = new JTextField(3);
		longLongSizeComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedLongLongSize();
			}
		});
		longLongSizeComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedLongLongSize();
			}
		});
	}

	private void setUpFloatSize() {
		floatSizeComponent = new JTextField(3);
		floatSizeComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedFloatSize();
			}
		});
		floatSizeComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedFloatSize();
			}
		});
	}

	private void setUpDoubleSize() {
		doubleSizeComponent = new JTextField(3);
		doubleSizeComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedDoubleSize();
			}
		});
		doubleSizeComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedDoubleSize();
			}
		});
	}

	private void setUpLongDoubleSize() {
		longDoubleSizeComponent = new JTextField(3);
		longDoubleSizeComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedLongDoubleSize();
			}
		});
		longDoubleSizeComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedLongDoubleSize();
			}
		});
	}

	private void setUpAbsoluteMaxAlignment() {
		absoluteMaxAlignComponent = new JTextField(3);
		absoluteMaxAlignComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedAbsoluteMaxAlignment();
			}
		});
		absoluteMaxAlignComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedAbsoluteMaxAlignment();
			}
		});
	}

	private void setUpMachineAlignment() {
		machineAlignComponent = new JTextField(3);
		machineAlignComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedMachineAlignment();
			}
		});
		machineAlignComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedMachineAlignment();
			}
		});
	}

	private void setUpDefaultAlignment() {
		defaultAlignComponent = new JTextField(3);
		defaultAlignComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedDefaultAlignment();
			}
		});
		defaultAlignComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedDefaultAlignment();
			}
		});
	}

	private void setUpPointerAlignment() {
		pointerAlignComponent = new JTextField(3);
		pointerAlignComponent.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedDefaultPointerAlignment();
			}
		});
		pointerAlignComponent.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// TODO
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedDefaultPointerAlignment();
			}
		});
	}

	protected void updateSignedChar() {
		boolean isSigned = charIsSignedCheckbox.isSelected();
		dataOrganization.setCharIsSigned(isSigned);
	}

	protected void updatedCharSize() {
		int charSize = Integer.decode(charSizeComponent.getText()).intValue();
		dataOrganization.setCharSize(charSize);
	}

	protected void updatedWideCharSize() {
		int wcharSize = Integer.decode(wcharSizeComponent.getText()).intValue();
		dataOrganization.setWideCharSize(wcharSize);
	}

	protected void updatedShortSize() {
		int shortSize = Integer.decode(shortSizeComponent.getText()).intValue();
		dataOrganization.setShortSize(shortSize);
	}

	protected void updatedIntegerSize() {
		int integerSize = Integer.decode(integerSizeComponent.getText()).intValue();
		dataOrganization.setIntegerSize(integerSize);
	}

	protected void updatedLongSize() {
		int longSize = Integer.decode(longSizeComponent.getText()).intValue();
		dataOrganization.setLongSize(longSize);
	}

	protected void updatedLongLongSize() {
		int longLongSize = Integer.decode(longLongSizeComponent.getText()).intValue();
		dataOrganization.setLongLongSize(longLongSize);
	}

	protected void updatedFloatSize() {
		int floatSize = Integer.decode(floatSizeComponent.getText()).intValue();
		dataOrganization.setFloatSize(floatSize);
	}

	protected void updatedDoubleSize() {
		int doubleSize = Integer.decode(doubleSizeComponent.getText()).intValue();
		dataOrganization.setDoubleSize(doubleSize);
	}

	protected void updatedLongDoubleSize() {
		int longDoubleSize = Integer.decode(longDoubleSizeComponent.getText()).intValue();
		dataOrganization.setLongDoubleSize(longDoubleSize);
	}

	protected void updatedAbsoluteMaxAlignment() {
		String maxAlignString = absoluteMaxAlignComponent.getText().toLowerCase();
		int absoluteMax =
			("none".equals(maxAlignString)) ? 0 : Integer.decode(maxAlignString).intValue();
		dataOrganization.setAbsoluteMaxAlignment(absoluteMax);
	}

	protected void updatedMachineAlignment() {
		int machineAlignment = Integer.decode(machineAlignComponent.getText()).intValue();
		dataOrganization.setMachineAlignment(machineAlignment);
	}

	protected void updatedDefaultAlignment() {
		int defaultAlignment = Integer.decode(defaultAlignComponent.getText()).intValue();
		dataOrganization.setDefaultAlignment(defaultAlignment);
	}

	protected void updatedDefaultPointerAlignment() {
		int defaultPointerAlignment = Integer.decode(pointerAlignComponent.getText()).intValue();
		dataOrganization.setDefaultPointerAlignment(defaultPointerAlignment);
	}

}
