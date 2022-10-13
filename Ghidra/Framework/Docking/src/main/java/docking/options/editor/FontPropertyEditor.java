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
import java.awt.event.ActionListener;
import java.beans.PropertyEditorSupport;
import java.util.*;
import java.util.List;
import java.util.stream.*;

import javax.swing.*;

import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;
import ghidra.util.Swing;

/**
 * Property Editor for editing {@link Font}s
 */
public class FontPropertyEditor extends PropertyEditorSupport {
	public final static String SAMPLE_STRING = "ABCabc \u00a9\u00ab\u00a7\u0429\u05d1\u062c\u4eb9";

	private FontChooserPanel fontChooserPanel;

	@Override
	public Component getCustomEditor() {
		fontChooserPanel = new FontChooserPanel();
		fontChooserPanel.updateControls((Font) getValue());
		return fontChooserPanel;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public void setValue(Object value) {
		if (fontChooserPanel != null) {
			fontChooserPanel.updateControls((Font) value);
		}
		if (!Objects.equals(value, getValue())) {
			super.setValue(value);
		}
	}

	class FontChooserPanel extends JPanel {

		private GDLabel previewLabel;
		private GComboBox<FontWrapper> fontCombo;
		private GComboBox<Integer> sizeCombo;
		private GComboBox<String> styleCombo;
		private ActionListener actionListener = e -> fontChanged();
		private List<FontWrapper> systemFontNames;

		public FontChooserPanel() {
			build();
		}

		public void updateControls(Font font) {
			if (font == null) {
				return;
			}
			updatePreviewLabel(font);

			fontCombo.removeActionListener(actionListener);
			sizeCombo.removeActionListener(actionListener);
			styleCombo.removeActionListener(actionListener);

			FontWrapper fontWrapper = new FontWrapper(font.getName());
			updateComboBoxModeIfNeeded(fontWrapper);

			int styleChoice = font.getStyle();
			int size = font.getSize();
			fontCombo.setSelectedItem(fontWrapper);
			sizeCombo.setSelectedItem(size);
			styleCombo.setSelectedIndex(styleChoice);

			fontCombo.addActionListener(actionListener);
			sizeCombo.addActionListener(actionListener);
			styleCombo.addActionListener(actionListener);

		}

		private void updateComboBoxModeIfNeeded(FontWrapper fontWrapper) {
			if (systemFontNames.contains(fontWrapper)) {
				return;
			}
			systemFontNames.add(fontWrapper);
			DefaultComboBoxModel<FontWrapper> model =
				new DefaultComboBoxModel<>(systemFontNames.toArray(new FontWrapper[0]));
			fontCombo.setModel(model);
		}

		private void build() {
			setLayout(new BorderLayout());
			add(buildTopPanel(), BorderLayout.NORTH);
			add(buildPreviewLabel(), BorderLayout.CENTER);
		}

		private Component buildTopPanel() {
			JPanel panel = new JPanel(new FlowLayout(SwingConstants.CENTER, 10, 0));
			panel.add(buildFontNamePanel());
			panel.add(buildSizePanel());
			panel.add(buildStylePanel());
			return panel;
		}

		private Component buildPreviewLabel() {
			previewLabel = new GDLabel(SAMPLE_STRING);
			previewLabel.setPreferredSize(new Dimension(350, 50));
			previewLabel.setHorizontalAlignment(SwingConstants.CENTER);
			previewLabel.setVerticalAlignment(SwingConstants.CENTER);
			previewLabel.setMinimumSize(new Dimension(300, 50));
			return previewLabel;
		}

		private Component buildStylePanel() {
			JPanel panel = new JPanel(new GridLayout(2, 1));

			GDLabel styleLabel = new GDLabel("Styles");
			styleLabel.setFont(getFont().deriveFont(1));
			styleLabel.setHorizontalAlignment(SwingConstants.CENTER);
			panel.add(styleLabel);

			styleCombo =
				new GComboBox<>(new String[] { "PLAIN", "BOLD", "ITALIC", "BOLD & ITALIC" });
			styleCombo.setMaximumRowCount(9);
			styleCombo.addActionListener(actionListener);
			panel.add(styleCombo);

			return panel;
		}

		private Component buildSizePanel() {
			JPanel panel = new JPanel(new GridLayout(2, 1));

			GDLabel sizeLabel = new GDLabel("Sizes");
			sizeLabel.setFont(getFont().deriveFont(1));
			sizeLabel.setHorizontalAlignment(SwingConstants.CENTER);
			panel.add(sizeLabel);

			sizeCombo =
				new GComboBox<>(IntStream.rangeClosed(1, 72).boxed().toArray(Integer[]::new));
			sizeCombo.setMaximumRowCount(9);
			sizeCombo.setMaximumRowCount(9);
			sizeCombo.addActionListener(actionListener);
			panel.add(sizeCombo);

			return panel;
		}

		private Component buildFontNamePanel() {
			JPanel panel = new JPanel(new GridLayout(2, 1));

			GDLabel fontLabel = new GDLabel("Fonts");
			fontLabel.setFont(getFont().deriveFont(1));
			fontLabel.setHorizontalAlignment(SwingConstants.CENTER);
			panel.add(fontLabel);

			systemFontNames = getSystemFontNames();
			fontCombo = new GComboBox<>(systemFontNames.toArray(new FontWrapper[0]));
			fontCombo.setMaximumRowCount(9);
			fontCombo.addActionListener(actionListener);
			panel.add(fontCombo);

			return panel;
		}

		private List<FontWrapper> getSystemFontNames() {
			GraphicsEnvironment gEnv = GraphicsEnvironment.getLocalGraphicsEnvironment();
			Stream<String> stream = Arrays.stream(gEnv.getAvailableFontFamilyNames());
			List<FontWrapper> collect =
				stream.map(s -> new FontWrapper(s)).collect(Collectors.toList());
			Collections.sort(collect);
			return new ArrayList<>(collect);
		}

		private void fontChanged() {
			FontWrapper fontWrapper = (FontWrapper) fontCombo.getSelectedItem();
			String fontNameChoice = fontWrapper.getFontName();
			int styleChoice = styleCombo.getSelectedIndex();
			int sizeChoice = (Integer) sizeCombo.getSelectedItem();
			Font font = new Font(fontNameChoice, styleChoice, sizeChoice);
			updatePreviewLabel(font);
			// allows debugging without hanging amazon aws
			Swing.runLater(() -> setValue(font));
		}

		private void updatePreviewLabel(Font font) {
			previewLabel.setFont(font);
			FontMetrics fm = previewLabel.getFontMetrics(font);
			int height = fm.getHeight();
			Dimension d = previewLabel.getSize();
			if (d.height < height) {
				d = new Dimension(d.width, height);
				previewLabel.setPreferredSize(d);
			}
			previewLabel.invalidate();

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
				result =
					prime * result + ((fontName == null) ? 0 : fontName.toLowerCase().hashCode());
				return result;
			}

			@Override
			public int compareTo(FontWrapper otherWrapper) {
				return fontName.compareToIgnoreCase(otherWrapper.fontName);
			}
		}

	}

}
