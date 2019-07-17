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

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import ghidra.util.HelpLocation;

public class PrintOptionsDialog extends DialogComponentProvider {

	private final Font HEADER_FONT = new Font("SansSerif", Font.PLAIN, 10);
	private final FontMetrics HEADER_METRICS = rootPanel.getFontMetrics(HEADER_FONT);

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
		rangePanel.add(selection);
		group.add(selection);
		selection.setEnabled(selectionEnabled);
		visible = new GRadioButton("Code visible on screen");
		visible.addKeyListener(key);
		rangePanel.add(visible);
		group.add(visible);
		view = new GRadioButton("Current view");
		view.addKeyListener(key);
		rangePanel.add(view);
		group.add(view);

		JPanel headerPanel = new JPanel();
		headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.X_AXIS));
		headerPanel.setBorder(BorderFactory.createTitledBorder("Header and Footer"));

		title = new GCheckBox("Title");
		title.setSelected(true);
		title.addKeyListener(key);
		headerPanel.add(title);
		date = new GCheckBox("Date/Time");
		date.setSelected(true);
		date.addKeyListener(key);
		headerPanel.add(date);
		pageNum = new GCheckBox("Page Numbers");
		pageNum.setSelected(true);
		pageNum.addKeyListener(key);
		headerPanel.add(pageNum);

		JPanel optionsPanel = new JPanel();
		optionsPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
		optionsPanel.setBorder(BorderFactory.createTitledBorder("Other Print Options"));

		monochrome = new GCheckBox("Use Monochrome", true);
		monochrome.addKeyListener(key);
		optionsPanel.add(monochrome);

		outerPanel.add(rangePanel, BorderLayout.NORTH);
		outerPanel.add(headerPanel, BorderLayout.CENTER);
		outerPanel.add(optionsPanel, BorderLayout.SOUTH);

		setFocusComponent();

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
		return HEADER_FONT;
	}

	public FontMetrics getHeaderMetrics() {
		return HEADER_METRICS;
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
		return HEADER_METRICS.getMaxAscent() + HEADER_METRICS.getMaxDescent();
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
