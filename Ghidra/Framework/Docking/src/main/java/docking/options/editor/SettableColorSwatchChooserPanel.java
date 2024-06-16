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
import java.awt.datatransfer.Clipboard;
import java.awt.event.*;
import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.colorchooser.AbstractColorChooserPanel;
import javax.swing.colorchooser.ColorSelectionModel;
import javax.swing.event.*;
import javax.swing.text.Document;

import docking.dnd.GClipboard;
import docking.dnd.StringTransferable;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.util.ColorUtils;
import ghidra.util.WebColors;
import ghidra.util.layout.HorizontalLayout;

public class SettableColorSwatchChooserPanel extends AbstractColorChooserPanel {

	private SwatchPanel swatchPanel;
	private RecentSwatchPanel recentSwatchPanel;
	private HistorySwatchPanel historySwatchPanel;
	private JTextField colorNameField;
	private GDLabel colorValueLabel;

	private MainSwatchListener mainSwatchListener;
	private MouseListener recentSwatchListener;
	private MouseListener historySwatchListener;
	private DocumentListener colorNameListener;
	private ChangeListener colorValueUpdateListener;

	private String recentText = UIManager.getString("ColorChooser.swatchesRecentText");
	private List<Color> historyColors;

	public void setHistoryColors(List<Color> historyColors) {
		this.historyColors = historyColors;
		if (historySwatchPanel != null) {
			historySwatchPanel.setHistoryColors(historyColors);
		}
	}

	public List<Color> getHistoryColors() {
		return historyColors;
	}

	public void setRecentColors(List<Color> recentColors) {
		if (recentSwatchPanel != null) {
			recentSwatchPanel.setRecentColors(recentColors);
		}
	}

	public List<Color> getRecentColors() {
		if (recentSwatchPanel != null) {
			return recentSwatchPanel.getRecentColors();
		}
		return Collections.emptyList();
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
				// return default value
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
		recentSwatchPanel.getAccessibleContext().setAccessibleName(recentText);

		mainSwatchListener = new MainSwatchListener();
		swatchPanel.addMouseListener(mainSwatchListener);
		recentSwatchListener = new RecentSwatchListener();
		recentSwatchPanel.addMouseListener(recentSwatchListener);

		LineBorder border = new LineBorder(Colors.BORDER);
		swatchPanel.setBorder(border);
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.weightx = 1.0;
		gbc.gridwidth = 2;
		gbc.gridheight = 2;
		gbc.weighty = 1.0;
		gbc.anchor = GridBagConstraints.PAGE_START;
		superHolder.add(swatchPanel, gbc);

		recentSwatchPanel.setBorder(border);

		JLabel recentLabel = new GLabel(recentText);
		recentLabel.setLabelFor(recentSwatchPanel);

		JPanel recentPanel = new JPanel(new BorderLayout());
		recentPanel.add(recentLabel, BorderLayout.NORTH);
		recentPanel.add(recentSwatchPanel, BorderLayout.CENTER);

		historySwatchPanel = new HistorySwatchPanel(historyColors);
		historySwatchPanel.addMouseListener(historySwatchListener);
		historySwatchListener = new HistorySwatchListener();
		historySwatchPanel.setBorder(border);

		JPanel historyPanel = new JPanel(new BorderLayout());
		JLabel historyLabel = new GLabel("History:");
		historyLabel.setLabelFor(historySwatchPanel);
		historyPanel.add(historyLabel, BorderLayout.NORTH);
		historyPanel.add(historySwatchPanel, BorderLayout.CENTER);

		JPanel recentAndHistoryPanel = new JPanel(new HorizontalLayout(10));
		recentAndHistoryPanel.add(recentPanel);
		recentAndHistoryPanel.add(historyPanel);

		gbc.gridx = 2;
		gbc.gridy = 0;
		gbc.weighty = 0.0;
		superHolder.add(Box.createHorizontalStrut(10));

		gbc.gridx = 3;
		gbc.gridy = 0;
		superHolder.add(recentAndHistoryPanel, gbc);

		JPanel colorValuePanel = createColorValuePanel();

		gbc.gridx = 0;
		gbc.gridy = 2;
		gbc.gridwidth = 4; // take all space on the bottom, below the swatch
		superHolder.add(colorValuePanel, gbc);

		add(superHolder);
	}

	private JPanel createColorValuePanel() {

		//
		// The Color Value Panel shows allows the user to enter colors by name, hex or rgb.   It
		// also displays the current chooser color value in a label that can be double-clicked to
		// copy the color info.
		//
		// The layout:
		// - Box of 2 items from left to right
		//  	Label
		// 		Text Field + Description
		//
		// - The second box is laid out from top to bottom
		// 		Text Field on top
		// 		Description label on bottom
		//
		JPanel colorValuePanel = new JPanel();
		colorValuePanel.setLayout(new BoxLayout(colorValuePanel, BoxLayout.LINE_AXIS));
		JPanel colorTextPanel = new JPanel();
		colorTextPanel.setLayout(new BoxLayout(colorTextPanel, BoxLayout.PAGE_AXIS));

		colorNameField = new JTextField(20);
		colorNameField.addKeyListener(new KeyAdapter() {

			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					updateColorFromColorNameField();
					e.consume();
				}
			}
		});
		Document document = colorNameField.getDocument();
		colorNameListener = new ColorNameListener();
		document.addDocumentListener(colorNameListener);

		GLabel colorNameLabel = new GLabel("Color Name: ");
		String colorNameTip = "Enter a Web Color name or a color value";

		colorValueLabel = new GDLabel();
		colorValueLabel.setForeground(Messages.HINT);
		colorValueLabel.setToolTipText("Double-click to copy color info");
		colorValueLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					Color color = getColorFromModel();
					String text =
						WebColors.toHexString(color).toUpperCase() + "  " +
							WebColors.toRgbString(color);
					String colorName = WebColors.toColorName(color);
					if (colorName != null) {
						text += "  " + colorName;
					}
					Clipboard systemClipboard = GClipboard.getSystemClipboard();
					StringTransferable transferable = new StringTransferable(text);
					systemClipboard.setContents(transferable, null);
				}
			}
		});

		colorValueLabel.setText("    "); // this creates the correct vertical spacing when empty

		ColorSelectionModel model = getColorSelectionModel();
		colorValueUpdateListener = e -> {

			Color color = getColorFromModel();
			recentSwatchPanel.setMostRecentColor(color);

			String text = WebColors.toHexString(color) + "  " + WebColors.toRgbString(color);
			String colorName = WebColors.toColorName(color);
			colorValueLabel.setToolTipText(colorName);
			colorValueLabel.setText(text);
		};
		model.addChangeListener(colorValueUpdateListener);

		colorNameLabel.setToolTipText(colorNameTip);
		colorNameField.setToolTipText(colorNameTip);

		JPanel colorTextParentPanel = new JPanel(); // flow layout to center on x-axis
		colorTextParentPanel.add(colorValueLabel);

		colorTextPanel.add(colorNameField);
		colorTextPanel.add(colorTextParentPanel);

		// add space between the text field and this label
		colorNameLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 5));

		// align both left-to-right items at the top of the container
		colorNameLabel.setAlignmentY(0);
		colorTextPanel.setAlignmentY(0);

		colorValuePanel.add(colorNameLabel);
		colorValuePanel.add(colorTextPanel);

		// add space between swatch and this panel
		colorValuePanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
		return colorValuePanel;
	}

	@Override
	public void uninstallChooserPanel(JColorChooser enclosingChooser) {
		ColorSelectionModel model = getColorSelectionModel();
		model.removeChangeListener(colorValueUpdateListener);

		super.uninstallChooserPanel(enclosingChooser);
		swatchPanel.removeMouseListener(mainSwatchListener);
		recentSwatchPanel.removeMouseListener(recentSwatchListener);
		historySwatchPanel.removeMouseListener(historySwatchListener);
		colorNameField.getDocument().removeDocumentListener(colorNameListener);

		removeAll();  // strip out all the sub-components
	}

	@Override
	public void updateChooser() {
		// stub
	}

	private class HistorySwatchListener extends MouseAdapter {
		@Override
		public void mousePressed(MouseEvent e) {
			Color color = historySwatchPanel.getColorForLocation(e.getX(), e.getY());
			getColorSelectionModel().setSelectedColor(color);
		}
	}

	private class RecentSwatchListener extends MouseAdapter {
		@Override
		public void mousePressed(MouseEvent e) {
			Color color = recentSwatchPanel.getColorForLocation(e.getX(), e.getY());
			getColorSelectionModel().setSelectedColor(color);
		}
	}

	private class MainSwatchListener extends MouseAdapter implements Serializable {
		@Override
		public void mousePressed(MouseEvent e) {
			Color color = swatchPanel.getColorForLocation(e.getX(), e.getY());
			getColorSelectionModel().setSelectedColor(color);
		}
	}

	private void updateColorFromColorNameField() {

		String text = colorNameField.getText();
		String colorText = text.replaceAll("\s", "");
		Color color = WebColors.getColor(colorText);

		if (color == null) {
			color = WebColors.getColor('#' + colorText);
		}

		if (color != null) {
			getColorSelectionModel().setSelectedColor(color);
		}
	}

	private class ColorNameListener implements DocumentListener {

		@Override
		public void changedUpdate(DocumentEvent e) {
			updateColorFromColorNameField();
		}

		@Override
		public void insertUpdate(DocumentEvent e) {
			updateColorFromColorNameField();
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			updateColorFromColorNameField();
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
		setBackground(Colors.BACKGROUND);
		setRequestFocusEnabled(false);
	}

	@Override
	public boolean isFocusTraversable() {
		return false;
	}

	protected void initValues() {
		// stub
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
				g.setColor(Colors.BORDER);
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
		// stub
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

	private List<Color> recentColors;

	RecentSwatchPanel() {
		initColors();
	}

	List<Color> getRecentColors() {
		return List.of(colors);
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
		}
	}

	void setMostRecentColor(Color c) {

		// Do not add duplicates next to each other; duplicates are ok if separated by other colors,
		// as this shows color choices over time and provides the user some context.
		Color lastColor = colors[0];
		if (Objects.equals(lastColor, c)) {
			return;
		}

		System.arraycopy(colors, 0, colors, 1, colors.length - 1);
		colors[0] = c;
		repaint();
	}

	void setRecentColors(List<Color> recentColors) {
		this.recentColors = recentColors;
		initColors();
	}
}

class HistorySwatchPanel extends SwatchPanel {
	private List<Color> historyColors;

	HistorySwatchPanel(List<Color> recentColors) {
		setHistoryColors(recentColors);
	}

	void setHistoryColors(List<Color> recentColors) {
		this.historyColors = recentColors;
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

		if (historyColors != null && historyColors.size() > 0) {
			int recentColorCount = historyColors.size();
			for (int i = 0; i < recentColorCount; i++) {
				colors[i] = historyColors.get(i);
			}
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
			colors[i] = ColorUtils.getColor(rawValues[(i * 3)], rawValues[(i * 3) + 1],
				rawValues[(i * 3) + 2]);
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
