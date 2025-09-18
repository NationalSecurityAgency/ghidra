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
package ghidra.app.plugin.core.datamgr.tree;

import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.button.GButton;
import docking.widgets.checkbox.GCheckBox;
import ghidra.app.util.HelpTopics;
import ghidra.util.HelpLocation;

/**
 * Data Types provider dialog to allow users to change the types that are filtered.
 */
public class DtFilterDialog extends DialogComponentProvider {

	private TypeComponent arraysComponent = new TypeComponent("Arrays");
	private TypeComponent enumsComponent = new TypeComponent("Enums");
	private TypeComponent functionsComponent = new TypeComponent("Functions");
	private TypeComponent pointersComponent = new TypeComponent("Pointers");
	private TypeComponent structuresComponent = new TypeComponent("Structures");
	private TypeComponent unionsComponent = new TypeComponent("Unions");

	private DtFilterState filterState;
	private boolean isCancelled;

	public DtFilterDialog(DtFilterState filterState) {
		super("Data Types Filter");
		this.filterState = filterState;

		addWorkPanel(buildWorkPanel());

		addOKButton();
		addCancelButton();

		setHelpLocation(new HelpLocation(HelpTopics.DATA_MANAGER, "Show Filter"));

		initCheckBoxes();
		setRememberSize(false);
	}

	@Override
	protected void cancelCallback() {
		super.cancelCallback();
		isCancelled = true;
	}

	@Override
	protected void okCallback() {
		close();
	}

	public boolean isCancelled() {
		return isCancelled;
	}

	public DtFilterState getFilterState() {
		DtFilterState newState = new DtFilterState();
		newState.setArraysFilter(arraysComponent.getFilter());
		newState.setEnumsFilter(enumsComponent.getFilter());
		newState.setFunctionsFilter(functionsComponent.getFilter());
		newState.setPointersFilter(pointersComponent.getFilter());
		newState.setStructuresFilter(structuresComponent.getFilter());
		newState.setUnionsFilter(unionsComponent.getFilter());
		return newState;
	}

	private JPanel buildWorkPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new GridLayout(0, 2));

		JLabel l1 = new JLabel("<html><b>Show");
		l1.setHorizontalAlignment(SwingConstants.LEFT);
		panel.add(l1);

		JLabel l2 = new JLabel("<html><b>Include Typedefs");
		l2.setHorizontalAlignment(SwingConstants.CENTER);
		panel.add(l2);

		panel.add(arraysComponent.getLeft());
		panel.add(arraysComponent.getRight());
		panel.add(enumsComponent.getLeft());
		panel.add(enumsComponent.getRight());
		panel.add(functionsComponent.getLeft());
		panel.add(functionsComponent.getRight());
		panel.add(pointersComponent.getLeft());
		panel.add(pointersComponent.getRight());
		panel.add(structuresComponent.getLeft());
		panel.add(structuresComponent.getRight());
		panel.add(unionsComponent.getLeft());
		panel.add(unionsComponent.getRight());

		GButton selectAll = new GButton("Select All");
		GButton deselectAll = new GButton("Deselect All");
		selectAll.addActionListener(e -> {
			allButtons().forEach(b -> b.setSelected(true));
		});
		deselectAll.addActionListener(e -> {
			allButtons().forEach(b -> b.setSelected(false));
		});

		// spacer above buttons 
		panel.add(Box.createRigidArea(new Dimension(10, 10)));
		panel.add(Box.createRigidArea(new Dimension(10, 10)));

		JPanel p1 = new JPanel();
		p1.setLayout(new BoxLayout(p1, BoxLayout.LINE_AXIS));
		p1.add(Box.createHorizontalGlue());
		p1.add(selectAll);
		p1.add(Box.createHorizontalGlue());

		JPanel p2 = new JPanel();
		p2.setLayout(new BoxLayout(p2, BoxLayout.LINE_AXIS));
		p2.add(Box.createHorizontalGlue());
		p2.add(deselectAll);
		p2.add(Box.createHorizontalGlue());

		panel.add(p1);
		panel.add(p2);

		return panel;
	}

	private List<AbstractButton> allButtons() {
		//@formatter:off
		return List.of(
			arraysComponent.typeCb,
			arraysComponent.typeDefCb,
			enumsComponent.typeCb,
			enumsComponent.typeDefCb,
			functionsComponent.typeCb,
			functionsComponent.typeDefCb,
			pointersComponent.typeCb,
			pointersComponent.typeDefCb,
			structuresComponent.typeCb,
			structuresComponent.typeDefCb,
			unionsComponent.typeCb,
			unionsComponent.typeDefCb
		);
		//@formatter:on
	}

	private void initCheckBoxes() {
		arraysComponent.init(filterState.getArraysFilter());
		enumsComponent.init(filterState.getEnumsFilter());
		functionsComponent.init(filterState.getFunctionsFilter());
		pointersComponent.init(filterState.getPointersFilter());
		structuresComponent.init(filterState.getStructuresFilter());
		unionsComponent.init(filterState.getUnionsFilter());
	}

	private class TypeComponent {

		private String type;
		private GCheckBox typeCb;
		private GCheckBox typeDefCb;

		TypeComponent(String type) {
			this.type = type;
			this.typeCb = new GCheckBox(type);
			this.typeDefCb = new GCheckBox();
			this.typeDefCb.setName(type + "TypeDefs");
		}

		JComponent getLeft() {
			return typeCb;
		}

		JComponent getRight() {
			JPanel panel = new JPanel();
			panel.setLayout(new BoxLayout(panel, BoxLayout.LINE_AXIS));
			panel.add(Box.createHorizontalGlue());
			panel.add(typeDefCb);
			panel.add(Box.createHorizontalGlue());
			return panel;
		}

		void init(DtTypeFilter typeFilter) {
			typeCb.setSelected(typeFilter.isTypeActive());
			typeDefCb.setSelected(typeFilter.isTypeDefActive());
		}

		DtTypeFilter getFilter() {
			DtTypeFilter filter = new DtTypeFilter(type);
			filter.setTypeActive(typeCb.isSelected());
			filter.setTypeDefActive(typeDefCb.isSelected());
			return filter;
		}
	}
}
