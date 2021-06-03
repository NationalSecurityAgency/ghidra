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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyEditorSupport;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.IntStream;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;

/**
 * This Bean FontEditor displays a String with the current selected font name,
 * style and size attributes.
 */
public class FontPropertyEditor extends PropertyEditorSupport {
	private Font font;
//    private JLabel previewLabel = new GDLabel();
	private final static String SAMPLE_STRING = "ABCabc \u00a9\u00ab\u00a7\u0429\u05d1\u062c\u4eb9";
	private JButton previewButton = new JButton(SAMPLE_STRING);

	/**
	 * The default constructor.
	 *
	 */
	public FontPropertyEditor() {

		previewButton.addActionListener(e -> {
			// show the editor to get the user value
			showDialog();

			// now set the new value
			previewButton.setFont(font);
		});

//        previewLabel.addMouseListener( new MouseAdapter() {
//            @Override
//            public void mouseClicked( MouseEvent evt ) {
//                // show the editor to get the user value
//                showDialog();
//
//                // now set the new value
//                previewLabel.setFont( font );
//            }
//        } );
	}

	public void showDialog() {
		EditorProvider provider = new EditorProvider(new FontPanel());
		DockingWindowManager.showDialog(previewButton, provider);
		previewButton.repaint();
	}

	@Override
	public void setValue(Object o) {
		font = (Font) o;
		previewButton.setFont(font);

		// set the font values on the widget
	}

	@Override
	public Object getValue() {
		return font;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public Component getCustomEditor() {
		return previewButton;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class FontPanel extends JPanel implements ActionListener {
		JLabel fontLabel, sizeLabel, styleLabel;
		JLabel fontStringLabel;
		JComboBox<FontWrapper> fonts;
		JComboBox<Integer> sizes;
		JComboBox<String> styles;
		int styleChoice;
		int sizeChoice;

		FontPanel() {
			init();
		}

		public void init() {
			this.setLayout(new BorderLayout());

			JPanel topPanel = new JPanel();
			JPanel fontPanel = new JPanel();
			JPanel sizePanel = new JPanel();
			JPanel stylePanel = new JPanel();
			JPanel sizeAndStylePanel = new JPanel();

			topPanel.setLayout(new BorderLayout());
			fontPanel.setLayout(new GridLayout(2, 1));
			sizePanel.setLayout(new GridLayout(2, 1));
			stylePanel.setLayout(new GridLayout(2, 1));
			sizeAndStylePanel.setLayout(new BorderLayout());

			topPanel.add(BorderLayout.WEST, fontPanel);
			sizeAndStylePanel.add(BorderLayout.WEST, sizePanel);
			sizeAndStylePanel.add(BorderLayout.CENTER, stylePanel);
			topPanel.add(BorderLayout.CENTER, sizeAndStylePanel);

			fontStringLabel = new GDLabel(FontPropertyEditor.SAMPLE_STRING);
			fontStringLabel.setPreferredSize(new Dimension(350, 50));
			fontStringLabel.setHorizontalAlignment(SwingConstants.CENTER);
			fontStringLabel.setFont(font);
			topPanel.add(BorderLayout.SOUTH, fontStringLabel);

			add(BorderLayout.NORTH, topPanel);

			fontLabel = new GDLabel("Fonts");
			Font newFont = getFont().deriveFont(1);
			fontLabel.setFont(newFont);
			fontLabel.setHorizontalAlignment(SwingConstants.CENTER);
			fontPanel.add(fontLabel);

			sizeLabel = new GDLabel("Sizes");
			sizeLabel.setFont(newFont);
			sizeLabel.setHorizontalAlignment(SwingConstants.CENTER);
			sizePanel.add(sizeLabel);

			styleLabel = new GDLabel("Styles");
			styleLabel.setFont(newFont);
			styleLabel.setHorizontalAlignment(SwingConstants.CENTER);
			stylePanel.add(styleLabel);

			GraphicsEnvironment gEnv = GraphicsEnvironment.getLocalGraphicsEnvironment();

			String envfonts[] = gEnv.getAvailableFontFamilyNames();
			List<FontWrapper> list = new ArrayList<>(envfonts.length);
			for (String envfont : envfonts) {
				list.add(new FontWrapper(envfont));
			}
			Collections.sort(list);
			fonts = new GComboBox<>(list.toArray(new FontWrapper[envfonts.length]));
			fonts.setMaximumRowCount(9);
			FontWrapper fontWrapper = new FontWrapper(font.getName());
			fontPanel.add(fonts);
			fonts.setSelectedItem(fontWrapper);

			sizes = new GComboBox<>(IntStream.rangeClosed(1, 72).boxed().toArray(Integer[]::new));
			sizes.setMaximumRowCount(9);
			sizePanel.add(sizes);
			sizeChoice = font.getSize();
			sizes.setSelectedItem(sizeChoice);
			sizes.setMaximumRowCount(9);

			styles = new GComboBox<>(new String[] { "PLAIN", "BOLD", "ITALIC", "BOLD & ITALIC" });
			styles.setMaximumRowCount(9);
			stylePanel.add(styles);
			styleChoice = font.getStyle();
			styles.setSelectedIndex(styleChoice);
			fonts.addActionListener(this);
			styles.addActionListener(this);
			sizes.addActionListener(this);
		}

		@Override
		public void actionPerformed(ActionEvent event) {
			// get values of panels
			// set the editors new font
			Object list = event.getSource();

			String fontNameChoice = font.getName();
			if (list == fonts) {
				FontWrapper fontWrapper = (FontWrapper) fonts.getSelectedItem();
				fontNameChoice = fontWrapper.getFontName();
			}
			else if (list == styles) {
				styleChoice = styles.getSelectedIndex();
			}
			else {
				sizeChoice = (Integer) sizes.getSelectedItem();
			}

			font = new Font(fontNameChoice, styleChoice, sizeChoice);
			fontStringLabel.setFont(font);
			FontMetrics fm = fontStringLabel.getFontMetrics(font);
			int height = fm.getHeight();
			Dimension d = fontStringLabel.getSize();
			if (d.height < height) {
				d = new Dimension(d.width, height);
				fontStringLabel.setPreferredSize(d);
			}
			fontStringLabel.invalidate();

			setValue(font);
			FontPropertyEditor.this.firePropertyChange();
		}
	}

	class EditorProvider extends DialogComponentProvider {
		private Font originalFont = font;

		EditorProvider(JPanel contentPanel) {
			super("Font Editor", true);

			addWorkPanel(contentPanel);
			addOKButton();
			addCancelButton();
		}

		@Override
		protected void okCallback() {
			close();
		}

		@Override
		protected void cancelCallback() {
			font = originalFont;
			super.cancelCallback();
		}
	}

	// A wrapper class created so that the names of fonts are comparable ignoring case
	private class FontWrapper implements Comparable<FontWrapper> {
		private final String fontName;

		private FontWrapper(String fontName) {
			this.fontName = fontName;
		}

		private String getFontName() {
			return fontName;
		}

		@Override
		public String toString() {
			return fontName;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}

			if (obj == null) {
				return false;
			}

			if (!getClass().equals(obj.getClass())) {
				return false;
			}

			FontWrapper otherWrapper = (FontWrapper) obj;
			return fontName.toLowerCase().equals(otherWrapper.fontName.toLowerCase());
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((fontName == null) ? 0 : fontName.toLowerCase().hashCode());
			return result;
		}

		@Override
		public int compareTo(FontWrapper otherWrapper) {
			return fontName.compareToIgnoreCase(otherWrapper.fontName);
		}
	}
}
