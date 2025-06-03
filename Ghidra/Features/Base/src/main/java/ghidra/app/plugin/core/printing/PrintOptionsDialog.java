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
package ghidra.app.plugin.core.printing;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

import docking.ReusableDialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import generic.theme.Gui;
import ghidra.util.HelpLocation;

public class PrintOptionsDialog extends ReusableDialogComponentProvider {

	private static final String FONT_ID = "font.print";
	private boolean selectionEnabled;
	private boolean cancelled = false;

	private JRadioButton selection;
	private JRadioButton visible;
	private JRadioButton view;
	private JCheckBox monochrome;

	private JCheckBox title;
	private JCheckBox date;
	private JCheckBox pageNum;

	private ButtonGroup group;

	protected PrintOptionsDialog(boolean selectionEnabled) {
		super("Print Options", true, false, true, false);
		setResizable(false);
		this.selectionEnabled = selectionEnabled;

		addWorkPanel(create());
		addOKButton();
		addCancelButton();
		setHelpLocation(new HelpLocation("PrintingPlugin", "Print"));
	}

	@Override
	protected void cancelCallback() {
		close();
		cancelled = true;
	}

	@Override
	protected void okCallback() {
		close();
		cancelled = false;
	}

	JPanel create() {
		JPanel outerPanel = new JPanel(new BorderLayout());

		JPanel rangePanel = new JPanel();
		rangePanel.setLayout(new BoxLayout(rangePanel, BoxLayout.Y_AXIS));
		rangePanel.setBorder(BorderFactory.createTitledBorder("Print Range"));
		rangePanel.getAccessibleContext().setAccessibleName("Print Range");

		KeyListener key = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					((AbstractButton) e.getSource()).setSelected(true);
					okCallback();
				}
			}
		};

		group = new ButtonGroup();

		selection = new GRadioButton("Selected area(s)");
		selection.addKeyListener(key);
		selection.getAccessibleContext().setAccessibleName("Selected Area");
		rangePanel.add(selection);
		group.add(selection);
		selection.setEnabled(selectionEnabled);
		visible = new GRadioButton("Code visible on screen");
		visible.addKeyListener(key);
		visible.getAccessibleContext().setAccessibleName("Visible Code");
		rangePanel.add(visible);
		group.add(visible);
		view = new GRadioButton("Current view");
		view.addKeyListener(key);
		view.getAccessibleContext().setAccessibleName("Current View");
		rangePanel.add(view);
		group.add(view);

		JPanel headerPanel = new JPanel();
		headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.X_AXIS));
		headerPanel.setBorder(BorderFactory.createTitledBorder("Header and Footer"));
		headerPanel.getAccessibleContext().setAccessibleName("Info");

		title = new GCheckBox("Title");
		title.setSelected(true);
		title.addKeyListener(key);
		title.getAccessibleContext().setAccessibleName("Title");
		headerPanel.add(title);
		date = new GCheckBox("Date/Time");
		date.setSelected(true);
		date.addKeyListener(key);
		date.getAccessibleContext().setAccessibleName("Date/Time");
		headerPanel.add(date);
		pageNum = new GCheckBox("Page Numbers");
		pageNum.setSelected(true);
		pageNum.addKeyListener(key);
		pageNum.getAccessibleContext().setAccessibleName("Page Numbers");
		headerPanel.add(pageNum);

		JPanel optionsPanel = new JPanel();
		optionsPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
		optionsPanel.setBorder(BorderFactory.createTitledBorder("Other Print Options"));
		optionsPanel.getAccessibleContext().setAccessibleName("Other Options");

		monochrome = new GCheckBox("Use Monochrome", true);
		monochrome.addKeyListener(key);
		monochrome.getAccessibleContext().setAccessibleName("Monochrome");
		optionsPanel.add(monochrome);

		outerPanel.add(rangePanel, BorderLayout.NORTH);
		outerPanel.add(headerPanel, BorderLayout.CENTER);
		outerPanel.add(optionsPanel, BorderLayout.SOUTH);

		setFocusComponent();
		outerPanel.getAccessibleContext().setAccessibleName("Print Options");
		return outerPanel;
	}

	public boolean getSelection() {
		return selection.isSelected();
	}

	public boolean getVisible() {
		return visible.isSelected();
	}

	public boolean getView() {
		return view.isSelected();
	}

	public boolean getPrintTitle() {
		return title.isSelected();
	}

	public boolean getPrintDate() {
		return date.isSelected();
	}

	public boolean getPrintPageNum() {
		return pageNum.isSelected();
	}

	public boolean isCancelled() {
		return cancelled;
	}

	public Font getHeaderFont() {
		return Gui.getFont(FONT_ID);
	}

	public FontMetrics getHeaderMetrics() {
		return rootPanel.getFontMetrics(getHeaderFont());
	}

	public boolean showHeader() {
		return getPrintTitle();
	}

	public boolean showFooter() {
		return getPrintDate() || getPrintPageNum();
	}

	public boolean getMonochrome() {
		return monochrome.isSelected();
	}

	public int getHeaderHeight() {
		FontMetrics metrics = getHeaderMetrics();
		return metrics.getMaxAscent() + metrics.getMaxDescent();
	}

	public void setSelectionEnabled(boolean selectionEnabled) {
		this.selectionEnabled = selectionEnabled;
		selection.setEnabled(selectionEnabled);
		selection.setSelected(selectionEnabled);
		if (!selectionEnabled) {
			view.setSelected(true);
		}
		setFocusComponent();
	}

	public void setFocusComponent() {
		if (selectionEnabled) {
			group.setSelected(selection.getModel(), true);
			setFocusComponent(selection);
		}
		else {
			group.setSelected(view.getModel(), true);
			setFocusComponent(view);
		}
	}
}
