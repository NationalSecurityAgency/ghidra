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
package docking.options.editor;

import java.awt.*;
import java.awt.event.*;
import java.io.Serializable;
import java.util.List;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.colorchooser.AbstractColorChooserPanel;

import docking.widgets.label.GHtmlLabel;
import docking.widgets.label.GLabel;
import ghidra.util.layout.VerticalLayout;

public class SettableColorSwatchChooserPanel extends AbstractColorChooserPanel {
	SwatchPanel swatchPanel;
	RecentSwatchPanel recentSwatchPanel;
	HistorySwatchPanel historySwatchPanel;
	MainSwatchListener mainSwatchListener;
	MouseListener recentSwatchListener;
	MouseListener historySwatchListener;

	private String recentStr = UIManager.getString("ColorChooser.swatchesRecentText");
	private List<Color> recentColors;

	public SettableColorSwatchChooserPanel(List<Color> recentColors) {
		setRecentColors(recentColors);
	}

	public void setRecentColors(List<Color> recentColors) {
		this.recentColors = recentColors;
		if (historySwatchPanel != null) {
			historySwatchPanel.setRecentColors(recentColors);
		}
	}

	@Override
	public String getDisplayName() {
		return UIManager.getString("ColorChooser.swatchesNameText");
	}

	private int overriddenGetInt(Object key, int defaultValue) {
		Object value = UIManager.get(key);

		if (value instanceof Integer) {
			return ((Integer) value).intValue();
		}
		if (value instanceof String) {
			try {
				return Integer.parseInt((String) value);
			}
			catch (NumberFormatException nfe) {
			}
		}
		return defaultValue;
	}

	@Override
	public int getMnemonic() {
		return overriddenGetInt("ColorChooser.swatchesMnemonic", -1);
	}

	@Override
	public int getDisplayedMnemonicIndex() {
		return overriddenGetInt("ColorChooser.swatchesDisplayedMnemonicIndex", -1);
	}

	@Override
	public Icon getSmallDisplayIcon() {
		return null;
	}

	@Override
	public Icon getLargeDisplayIcon() {
		return null;
	}

	/**
	 * The background color, foreground color, and font are already set to the
	 * defaults from the defaults table before this method is called.
	 */
	@Override
	public void installChooserPanel(JColorChooser enclosingChooser) {
		super.installChooserPanel(enclosingChooser);
	}

	@Override
	protected void buildChooser() {

		GridBagLayout gb = new GridBagLayout();
		GridBagConstraints gbc = new GridBagConstraints();
		JPanel superHolder = new JPanel(gb);

		swatchPanel = new MainSwatchPanel();
		swatchPanel.getAccessibleContext().setAccessibleName(getDisplayName());

		recentSwatchPanel = new RecentSwatchPanel();
		recentSwatchPanel.getAccessibleContext().setAccessibleName(recentStr);

		mainSwatchListener = new MainSwatchListener();
		swatchPanel.addMouseListener(mainSwatchListener);
		recentSwatchListener = new RecentSwatchListener();
		recentSwatchPanel.addMouseListener(recentSwatchListener);

		Border border =
			new CompoundBorder(new LineBorder(Color.black), new LineBorder(Color.white));
		swatchPanel.setBorder(border);
		gbc.weightx = 1.0;
		gbc.gridwidth = 2;
		gbc.gridheight = 2;
		gbc.weighty = 1.0;
		superHolder.add(swatchPanel, gbc);

		recentSwatchPanel.addMouseListener(recentSwatchListener);
		recentSwatchPanel.setBorder(border);
		JPanel recentLabelHolder = new JPanel(new BorderLayout());
		JLabel l = new GHtmlLabel(recentStr);
		l.setLabelFor(recentSwatchPanel);
		recentLabelHolder.add(l, BorderLayout.NORTH);
		gbc.weighty = 0.0;
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.gridheight = 1;
//superHolder.add( recentLabelHolder, gbc );
//superHolder.add( recentSwatchPanel, gbc );  

		// GHIDRA
		historySwatchPanel = new HistorySwatchPanel(recentColors);
		historySwatchListener = new HistorySwatchListener();
		historySwatchPanel.addMouseListener(historySwatchListener);
		historySwatchPanel.setBorder(border);
		JPanel historyLabelHolder = new JPanel(new BorderLayout());
		JLabel historyLabel = new GLabel("History:");
		historyLabel.setLabelFor(historySwatchPanel);
		historyLabelHolder.add(historyLabel, BorderLayout.NORTH);
		gbc.weighty = 0.0;
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.gridheight = 1;
//superHolder.add( historyLabelHolder, gbc );
//superHolder.add( historySwatchPanel, gbc );          

		JPanel recentAndHistoryPanel = new JPanel(new VerticalLayout(1));
		recentAndHistoryPanel.add(recentLabelHolder);
		recentAndHistoryPanel.add(recentSwatchPanel);
		recentAndHistoryPanel.add(Box.createVerticalStrut(2));
		recentAndHistoryPanel.add(historyLabelHolder);
		recentAndHistoryPanel.add(historySwatchPanel);
		superHolder.add(Box.createHorizontalStrut(5));
		superHolder.add(recentAndHistoryPanel);

		add(superHolder);

	}

	@Override
	public void uninstallChooserPanel(JColorChooser enclosingChooser) {
		super.uninstallChooserPanel(enclosingChooser);
		swatchPanel.removeMouseListener(mainSwatchListener);
		recentSwatchPanel.removeMouseListener(recentSwatchListener);
		historySwatchPanel.removeMouseListener(historySwatchListener);
		swatchPanel = null;
		recentSwatchPanel = null;
		recentSwatchListener = null;
		mainSwatchListener = null;
		removeAll();  // strip out all the sub-components
	}

	@Override
	public void updateChooser() {
	}

	class HistorySwatchListener extends MouseAdapter {
		@Override
		public void mousePressed(MouseEvent e) {
			Color color = historySwatchPanel.getColorForLocation(e.getX(), e.getY());
			getColorSelectionModel().setSelectedColor(color);
		}
	}

	class RecentSwatchListener extends MouseAdapter {
		@Override
		public void mousePressed(MouseEvent e) {
			Color color = recentSwatchPanel.getColorForLocation(e.getX(), e.getY());
			getColorSelectionModel().setSelectedColor(color);
		}
	}

	class MainSwatchListener extends MouseAdapter implements Serializable {
		@Override
		public void mousePressed(MouseEvent e) {
			Color color = swatchPanel.getColorForLocation(e.getX(), e.getY());
			getColorSelectionModel().setSelectedColor(color);
			recentSwatchPanel.setMostRecentColor(color);
		}
	}
}

class SwatchPanel extends JPanel {

	protected Color[] colors;
	protected Dimension swatchSize;
	protected Dimension numSwatches;
	protected Dimension gap;

	public SwatchPanel() {
		initValues();
		initColors();
		setToolTipText(""); // register for events
		setOpaque(true);
		setBackground(Color.white);
		setRequestFocusEnabled(false);
	}

	@Override
	public boolean isFocusTraversable() {
		return false;
	}

	protected void initValues() {
	}

	@Override
	public void paintComponent(Graphics g) {
		g.setColor(getBackground());
		g.fillRect(0, 0, getWidth(), getHeight());
		for (int row = 0; row < numSwatches.height; row++) {
			for (int column = 0; column < numSwatches.width; column++) {
				g.setColor(getColorForCell(column, row));
				int x;
				if ((!this.getComponentOrientation().isLeftToRight()) &&
					(this instanceof RecentSwatchPanel)) {
					x = (numSwatches.width - column - 1) * (swatchSize.width + gap.width);
				}
				else {
					x = column * (swatchSize.width + gap.width);
				}
				int y = row * (swatchSize.height + gap.height);
				g.fillRect(x, y, swatchSize.width, swatchSize.height);
				g.setColor(Color.black);
				g.drawLine(x + swatchSize.width - 1, y, x + swatchSize.width - 1,
					y + swatchSize.height - 1);
				g.drawLine(x, y + swatchSize.height - 1, x + swatchSize.width - 1,
					y + swatchSize.height - 1);
			}
		}
	}

	@Override
	public Dimension getPreferredSize() {
		int x = numSwatches.width * (swatchSize.width + gap.width) - 1;
		int y = numSwatches.height * (swatchSize.height + gap.height) - 1;
		return new Dimension(x, y);
	}

	protected void initColors() {

	}

	@Override
	public String getToolTipText(MouseEvent e) {
		Color color = getColorForLocation(e.getX(), e.getY());
		return color.getRed() + ", " + color.getGreen() + ", " + color.getBlue();
	}

	public Color getColorForLocation(int x, int y) {
		int column;
		if ((!this.getComponentOrientation().isLeftToRight()) &&
			(this instanceof RecentSwatchPanel)) {
			column = numSwatches.width - x / (swatchSize.width + gap.width) - 1;
		}
		else {
			column = x / (swatchSize.width + gap.width);
		}
		int row = y / (swatchSize.height + gap.height);
		return getColorForCell(column, row);
	}

	private Color getColorForCell(int column, int row) {
		return colors[(row * numSwatches.width) + column]; // (NOTE) - change data orientation here
	}
}

class RecentSwatchPanel extends SwatchPanel {

	RecentSwatchPanel() {
		initColors();
	}

	@Override
	protected void initValues() {
		swatchSize = UIManager.getDimension("ColorChooser.swatchesRecentSwatchSize");
		numSwatches = new Dimension(5, 7);
		gap = new Dimension(1, 1);
	}

	@Override
	protected void initColors() {
		Color defaultRecentColor = UIManager.getColor("ColorChooser.swatchesDefaultRecentColor");
		int numColors = numSwatches.width * numSwatches.height;

		colors = new Color[numColors];
		for (int i = 0; i < numColors; i++) {
			colors[i] = defaultRecentColor;
		}
	}

	public void setMostRecentColor(Color c) {

		System.arraycopy(colors, 0, colors, 1, colors.length - 1);
		colors[0] = c;
		repaint();
	}

}

class HistorySwatchPanel extends SwatchPanel {
	private List<Color> recentColors;

	HistorySwatchPanel(List<Color> recentColors) {
		setRecentColors(recentColors);
	}

	void setRecentColors(List<Color> recentColors) {
		this.recentColors = recentColors;
		initColors();
	}

	@Override
	protected void initValues() {
		swatchSize = UIManager.getDimension("ColorChooser.swatchesRecentSwatchSize");
		numSwatches = new Dimension(5, 7);
		gap = new Dimension(1, 1);
	}

	@Override
	protected void initColors() {
		Color defaultRecentColor = UIManager.getColor("ColorChooser.swatchesDefaultRecentColor");
		int numColors = numSwatches.width * numSwatches.height;

		colors = new Color[numColors];
		for (int i = 0; i < numColors; i++) {
			colors[i] = defaultRecentColor;
		}

		if (recentColors != null && recentColors.size() > 0) {
			int recentColorCount = recentColors.size();
			for (int i = 0; i < recentColorCount; i++) {
				colors[i] = recentColors.get(i);
			}
			return;
		}
	}
}

class MainSwatchPanel extends SwatchPanel {

	@Override
	protected void initValues() {
		swatchSize = UIManager.getDimension("ColorChooser.swatchesSwatchSize");
		numSwatches = new Dimension(31, 9);
		gap = new Dimension(1, 1);
	}

	@Override
	protected void initColors() {
		int[] rawValues = initRawValues();
		int numColors = rawValues.length / 3;

		colors = new Color[numColors];
		for (int i = 0; i < numColors; i++) {
			colors[i] =
				new Color(rawValues[(i * 3)], rawValues[(i * 3) + 1], rawValues[(i * 3) + 2]);
		}
	}

	// @formatter:off
    private int[] initRawValues() {

        int[] rawValues = {     
            255, 255, 255, // first row.
            204, 255, 255,
            204, 204, 255,
            204, 204, 255,
            204, 204, 255,
            204, 204, 255,
            204, 204, 255,
            204, 204, 255,
            204, 204, 255,
            204, 204, 255,
            204, 204, 255,
            255, 204, 255,
            255, 204, 204,
            255, 204, 204,
            255, 204, 204,
            255, 204, 204,
            255, 204, 204,
            255, 204, 204,
            255, 204, 204,
            255, 204, 204,
            255, 204, 204,
            255, 255, 204,
            204, 255, 204,
            204, 255, 204,
            204, 255, 204,
            204, 255, 204,
            204, 255, 204,
            204, 255, 204,
            204, 255, 204,
            204, 255, 204,
            204, 255, 204,
            204, 204, 204,  // second row.
            153, 255, 255,
            153, 204, 255,
            153, 153, 255,
            153, 153, 255,
            153, 153, 255,
            153, 153, 255,
            153, 153, 255,
            153, 153, 255,
            153, 153, 255,
            204, 153, 255,
            255, 153, 255,
            255, 153, 204,
            255, 153, 153,
            255, 153, 153,
            255, 153, 153,
            255, 153, 153,
            255, 153, 153,
            255, 153, 153,
            255, 153, 153,
            255, 204, 153,
            255, 255, 153,
            204, 255, 153,
            153, 255, 153,
            153, 255, 153,
            153, 255, 153,
            153, 255, 153,
            153, 255, 153,
            153, 255, 153,
            153, 255, 153,
            153, 255, 204,
            204, 204, 204,  // third row
            102, 255, 255,
            102, 204, 255,
            102, 153, 255,
            102, 102, 255,
            102, 102, 255,
            102, 102, 255,
            102, 102, 255,
            102, 102, 255,
            153, 102, 255,
            204, 102, 255,
            255, 102, 255,
            255, 102, 204,
            255, 102, 153,
            255, 102, 102,
            255, 102, 102,
            255, 102, 102,
            255, 102, 102,
            255, 102, 102,
            255, 153, 102,
            255, 204, 102,
            255, 255, 102,
            204, 255, 102,
            153, 255, 102,
            102, 255, 102,
            102, 255, 102,
            102, 255, 102,
            102, 255, 102,
            102, 255, 102,
            102, 255, 153,
            102, 255, 204,
            153, 153, 153, // fourth row
            51, 255, 255,
            51, 204, 255,
            51, 153, 255,
            51, 102, 255,
            51, 51, 255,
            51, 51, 255,
            51, 51, 255,
            102, 51, 255,
            153, 51, 255,
            204, 51, 255,
            255, 51, 255,
            255, 51, 204,
            255, 51, 153,
            255, 51, 102,
            255, 51, 51,
            255, 51, 51,
            255, 51, 51,
            255, 102, 51,
            255, 153, 51,
            255, 204, 51,
            255, 255, 51,
            204, 255, 51,
            153, 244, 51,
            102, 255, 51,
            51, 255, 51,
            51, 255, 51,
            51, 255, 51,
            51, 255, 102,
            51, 255, 153,
            51, 255, 204,
            153, 153, 153, // Fifth row
            0, 255, 255,
            0, 204, 255,
            0, 153, 255,
            0, 102, 255,
            0, 51, 255,
            0, 0, 255,
            51, 0, 255,
            102, 0, 255,
            153, 0, 255,
            204, 0, 255,
            255, 0, 255,
            255, 0, 204,
            255, 0, 153,
            255, 0, 102,
            255, 0, 51,
            255, 0 , 0,
            255, 51, 0,
            255, 102, 0,
            255, 153, 0,
            255, 204, 0,
            255, 255, 0,
            204, 255, 0,
            153, 255, 0,
            102, 255, 0,
            51, 255, 0,
            0, 255, 0,
            0, 255, 51,
            0, 255, 102,
            0, 255, 153,
            0, 255, 204,
            102, 102, 102, // sixth row
            0, 204, 204,
            0, 204, 204,
            0, 153, 204,
            0, 102, 204,
            0, 51, 204,
            0, 0, 204,
            51, 0, 204,
            102, 0, 204,
            153, 0, 204,
            204, 0, 204,
            204, 0, 204,
            204, 0, 204,
            204, 0, 153,
            204, 0, 102,
            204, 0, 51,
            204, 0, 0,
            204, 51, 0,
            204, 102, 0,
            204, 153, 0,
            204, 204, 0,
            204, 204, 0,
            204, 204, 0,
            153, 204, 0,
            102, 204, 0,
            51, 204, 0,
            0, 204, 0,
            0, 204, 51,
            0, 204, 102,
            0, 204, 153,
            0, 204, 204, 
            102, 102, 102, // seventh row
            0, 153, 153,
            0, 153, 153,
            0, 153, 153,
            0, 102, 153,
            0, 51, 153,
            0, 0, 153,
            51, 0, 153,
            102, 0, 153,
            153, 0, 153,
            153, 0, 153,
            153, 0, 153,
            153, 0, 153,
            153, 0, 153,
            153, 0, 102,
            153, 0, 51,
            153, 0, 0,
            153, 51, 0,
            153, 102, 0,
            153, 153, 0,
            153, 153, 0,
            153, 153, 0,
            153, 153, 0,
            153, 153, 0,
            102, 153, 0,
            51, 153, 0,
            0, 153, 0,
            0, 153, 51,
            0, 153, 102,
            0, 153, 153,
            0, 153, 153,
            51, 51, 51, // eigth row
            0, 102, 102,
            0, 102, 102,
            0, 102, 102,
            0, 102, 102,
            0, 51, 102,
            0, 0, 102,
            51, 0, 102,
            102, 0, 102,
            102, 0, 102,
            102, 0, 102,
            102, 0, 102,
            102, 0, 102,
            102, 0, 102,
            102, 0, 102,
            102, 0, 51,
            102, 0, 0,
            102, 51, 0,
            102, 102, 0,
            102, 102, 0,
            102, 102, 0,
            102, 102, 0,
            102, 102, 0,
            102, 102, 0,
            102, 102, 0,
            51, 102, 0,
            0, 102, 0,
            0, 102, 51,
            0, 102, 102,
            0, 102, 102,
            0, 102, 102,
            0, 0, 0, // ninth row
            0, 51, 51,
            0, 51, 51,
            0, 51, 51,
            0, 51, 51,
            0, 51, 51,
            0, 0, 51,
            51, 0, 51,
            51, 0, 51,
            51, 0, 51,
            51, 0, 51,
            51, 0, 51,
            51, 0, 51,
            51, 0, 51,
            51, 0, 51,
            51, 0, 51,
            51, 0, 0,
            51, 51, 0,
            51, 51, 0,
            51, 51, 0,
            51, 51, 0,
            51, 51, 0,
            51, 51, 0,
            51, 51, 0,
            51, 51, 0,
            0, 51, 0,
            0, 51, 51,
            0, 51, 51,
            0, 51, 51,
            0, 51, 51,
            51, 51, 51 };
        return rawValues;
    }
    // @formatter:on
}
