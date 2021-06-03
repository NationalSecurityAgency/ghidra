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
package ghidra.app.util.viewer.options;

import java.awt.*;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.math.BigInteger;
import java.util.*;
import java.util.List;
import java.util.stream.IntStream;

import javax.swing.*;
import javax.swing.border.Border;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import docking.widgets.label.GDLabel;
import ghidra.GhidraOptions;
import ghidra.util.SystemUtilities;

/**
 * Class for displaying and manipulating field colors and fonts.
 */
public class OptionsGui extends JPanel {
	private static final long serialVersionUID = 1L;
	private static final Color DARK_GREEN = new Color(0, 128, 0);
	private static final Color BLUE_GREEN = new Color(0, 128, 64);
	private static final Color DARK_BLUE = new Color(0, 0, 128);
	private static final Color PALE_BLUE = new Color(128, 128, 255);
	private static final Color YELLOW_ORANGE = new Color(155, 150, 50);
	private static final Color PURPLE = new Color(155, 50, 155);
	private static final Color DEEP_PURPLE = new Color(75, 0, 130);
	private static final Color DARK_PURPLE = new Color(102, 0, 102);
	private static final Color DARK_CYAN = new Color(0, 102, 102);
	private static final Color DARK_ORANGE = new Color(255, 128, 0);
	private static final Color DARK_RED = new Color(130, 0, 75);
	private static final Highlight[] NO_HIGHLIGHTS = new Highlight[0];
	private static final HighlightFactory hlFactory =
		(field, text, cursorTextOffset) -> NO_HIGHLIGHTS;

	public static final ScreenElement COMMENT_AUTO =
		new ScreenElement("Comment, Automatic", Color.LIGHT_GRAY);
	public static final ScreenElement ADDRESS = new ScreenElement("Address", Color.BLACK);
	public static final ScreenElement BACKGROUND = new ScreenElement("Background", Color.WHITE);
	public static final ScreenElement BAD_REF_ADDR =
		new ScreenElement("Bad Reference Address", Color.RED);
	public static final ScreenElement BYTES = new ScreenElement("Bytes", Color.BLUE);
	public static final ScreenElement CONSTANT = new ScreenElement("Constant", BLUE_GREEN);
	public static final ScreenElement LABELS_UNREFD =
		new ScreenElement("Labels, Unreferenced", Color.BLACK);
	public static final ScreenElement ENTRY_POINT = new ScreenElement("Entry Point", Color.MAGENTA);
	public static final ScreenElement COMMENT_EOL =
		new ScreenElement("Comment, EOL", "EOL Comment", Color.BLUE);
	public static final ScreenElement EXT_REF_RESOLVED =
		new ScreenElement("External Reference, Resolved", Color.CYAN.darker().darker());
	public static final ScreenElement FIELD_NAME = new ScreenElement("Field Name", Color.BLACK);
	public static final ScreenElement FUN_CALL_FIXUP =
		new ScreenElement("Function Call-Fixup", new Color(255, 0, 204));
	public static final ScreenElement FUN_NAME = new ScreenElement("Function Name", Color.BLUE);
	public static final ScreenElement FUN_PARAMS =
		new ScreenElement("Function Parameters", Color.BLACK);
	public static final ScreenElement FUN_TAG = new ScreenElement("Function Tag", DARK_RED);
	public static final ScreenElement FUN_AUTO_PARAMS =
		new ScreenElement("Function Auto-Parameters", Color.GRAY);
	public static final ScreenElement FUN_RET_TYPE =
		new ScreenElement("Function Return Type", Color.BLACK);
	public static final ScreenElement COMMENT_REPEATABLE =
		new ScreenElement("Comment, Repeatable", DARK_ORANGE);
	public static final ScreenElement COMMENT_REF_REPEAT =
		new ScreenElement("Comment, Referenced Repeatable", new Color(190, 190, 255));
	public static final ScreenElement LABELS_LOCAL = new ScreenElement("Labels, Local", BLUE_GREEN);
	public static final ScreenElement MNEMONIC_OVERRIDE =
		new ScreenElement("Mnemonic, Override", new Color(255, 0, 204));
	public static final ScreenElement MNEMONIC = new ScreenElement("Mnemonic", DARK_BLUE);
	public static final ScreenElement FLOW_ARROW_NON_ACTIVE =
		new ScreenElement("Flow Arrow, Not Active", new Color(160, 160, 160));
	public static final ScreenElement FLOW_ARROW_ACTIVE =
		new ScreenElement("Flow Arrow, Active", Color.BLACK);
	public static final ScreenElement FLOW_ARROW_SELECTED =
		new ScreenElement("Flow Arrow, Selected", new Color(0, 200, 0));
	public static final ScreenElement LABELS_NON_PRIMARY =
		new ScreenElement("Labels, Non-primary", YELLOW_ORANGE);
	public static final ScreenElement COMMENT_PLATE =
		new ScreenElement("Comment, Plate", "Plate Comment", Color.GRAY);
	public static final ScreenElement COMMENT_POST =
		new ScreenElement("Comment, Post", "Post-Comment", Color.BLUE);
	public static final ScreenElement COMMENT_PRE =
		new ScreenElement("Comment, Pre", "Pre-Comment", DEEP_PURPLE);
	public static final ScreenElement LABELS_PRIMARY =
		new ScreenElement("Labels, Primary", DARK_BLUE);
	public static final ScreenElement SEPARATOR = new ScreenElement("Separator", Color.BLACK);
	public static final ScreenElement VARIABLE = new ScreenElement("Variable", PURPLE);
	public static final ScreenElement PARAMETER_CUSTOM =
		new ScreenElement("Parameter, Custom Storage", DARK_PURPLE);
	public static final ScreenElement PARAMETER_DYNAMIC =
		new ScreenElement("Parameter, Dynamic Storage", DARK_CYAN);
	public static final ScreenElement VERSION_TRAK = new ScreenElement("Version Track", PURPLE);
	public static final ScreenElement XREF = new ScreenElement("XRef", DARK_GREEN);
	public static final ScreenElement XREF_OFFCUT = new ScreenElement("XRef, Offcut", Color.GRAY);
	public static final ScreenElement XREF_READ = new ScreenElement("XRef Read", Color.BLUE);
	public static final ScreenElement XREF_WRITE = new ScreenElement("XRef Write", DARK_ORANGE);
	public static final ScreenElement XREF_OTHER = new ScreenElement("XRef Other", Color.BLACK);
	public static final ScreenElement REGISTERS = new ScreenElement("Registers", YELLOW_ORANGE);
	public static final ScreenElement UNDERLINE = new ScreenElement("Underline", PALE_BLUE);

	static ScreenElement[] elements = { ADDRESS, BACKGROUND, BAD_REF_ADDR, BYTES, COMMENT_AUTO,
		COMMENT_EOL, COMMENT_PLATE, COMMENT_POST, COMMENT_PRE, COMMENT_REPEATABLE,
		COMMENT_REF_REPEAT, CONSTANT, ENTRY_POINT, EXT_REF_RESOLVED, FIELD_NAME, FLOW_ARROW_ACTIVE,
		FLOW_ARROW_NON_ACTIVE, FUN_CALL_FIXUP, FUN_NAME, FUN_PARAMS, FUN_AUTO_PARAMS, FUN_RET_TYPE,
		FUN_TAG, LABELS_LOCAL, LABELS_NON_PRIMARY, LABELS_PRIMARY, LABELS_UNREFD, MNEMONIC,
		MNEMONIC_OVERRIDE, PARAMETER_CUSTOM, PARAMETER_DYNAMIC, REGISTERS, SEPARATOR, UNDERLINE,
		VARIABLE, VERSION_TRAK, XREF, XREF_OFFCUT, XREF_READ, XREF_WRITE, XREF_OTHER };

	private Map<Integer, FontMetrics> metricsMap = new HashMap<>();

	private JList<ScreenElement> namesList;
	private JColorChooser colorChooser;
	private JCheckBox globalBoldCheckbox;
	private JCheckBox globalItalicsCheckbox;
	private JCheckBox boldCheckbox;
	private JCheckBox italicsCheckbox;
	private JCheckBox customCheckbox;
	private JComboBox<Integer> fontSizeField;
	private JComboBox<String> fontNameField;
	private JPanel colorPanel;
	private int selectedIndex;
	private Font baseFont;
	private FontMetrics baseMetrics;
	private Layout[] layouts;
	private LayoutModelListener modelListener;
	private int maxWidth;
	private FieldPanel fieldPanel;
	private PropertyChangeListener propertyChangeListener;

	/**
	 * Constructor
	 * @param font the base font for the fields.
	 * @param listener the listener to be notified when options change.
	 */
	public OptionsGui(Font font, PropertyChangeListener listener) {
		propertyChangeListener = listener;
		setBaseFont(SystemUtilities.adjustForFontSizeOverride(font));
		genLayouts();
		buildPanel();
		fieldPanel.setBackgroundColor(BACKGROUND.getColor());

		// update the selected ScreenElement as the user clicks around
		fieldPanel.addFieldMouseListener((location, field, ev) -> {
			ScreenElementTextField elementField = (ScreenElementTextField) field;
			ScreenElement selectedElement = elementField.getScreenElement();
			namesList.setSelectedValue(selectedElement, true);
		});

		setSelectedFontName(baseFont.getName());
		fontSizeField.setSelectedItem(baseFont.getSize());

		namesList.setSelectedIndex(0);
		namesList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		namesList.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			int index = namesList.getSelectedIndex();
			if (index == -1) {
				namesList.setSelectedIndex(selectedIndex);
			}
			else {
				setSelectedIndex(index);
			}
		});

		setSelectedIndex(0);
		colorChooser.getSelectionModel().addChangeListener(e -> {
			Color c = colorChooser.getColor();
			elements[selectedIndex].setColor(c);
			colorPanel.setBackground(c);
			genLayouts();
			fieldPanel.setBackgroundColor(BACKGROUND.getColor());
			enableApply();
		});
		ActionListener styleListener = e -> {
			updateStyle();
			genLayouts();
			fieldPanel.setBackgroundColor(BACKGROUND.getColor());
			enableApply();
		};
		ActionListener familyListener = e -> {
			updateFonts();
			genLayouts();
			fieldPanel.setBackgroundColor(BACKGROUND.getColor());
			enableApply();
		};

		boldCheckbox.addActionListener(styleListener);
		italicsCheckbox.addActionListener(styleListener);
		customCheckbox.addActionListener(styleListener);

		globalBoldCheckbox.addActionListener(familyListener);
		globalItalicsCheckbox.addActionListener(familyListener);
		fontSizeField.addActionListener(familyListener);
		fontNameField.addActionListener(familyListener);

		globalBoldCheckbox.setSelected(baseFont.isBold());
		globalItalicsCheckbox.setSelected(baseFont.isItalic());

	}

	private void setSelectedFontName(String name) {
		int n = fontNameField.getItemCount();
		for (int i = 0; i < n; i++) {
			if (name.equalsIgnoreCase(fontNameField.getItemAt(i))) {
				fontNameField.setSelectedIndex(i);
				return;
			}
		}
	}

	/**
	 * callback for when the selected display field changes.
	 * @param index the index in the JList of the selected field.
	 */
	private void setSelectedIndex(int index) {
		selectedIndex = index;
		Color c = elements[selectedIndex].getColor();
		int style = elements[selectedIndex].getStyle();
		colorPanel.setBackground(c);
		colorChooser.setColor(c);
		if (style == -1) {
			customCheckbox.setSelected(false);
			boldCheckbox.setSelected(baseFont.isBold());
			italicsCheckbox.setSelected(baseFont.isItalic());
			boldCheckbox.setEnabled(false);
			italicsCheckbox.setEnabled(false);
		}
		else {
			customCheckbox.setSelected(true);
			boldCheckbox.setSelected((style & Font.BOLD) != 0);
			italicsCheckbox.setSelected((style & Font.ITALIC) != 0);
			boldCheckbox.setEnabled(true);
			italicsCheckbox.setEnabled(true);
		}
	}

	/**
	 * Sets the base font to be used by the fields.
	 */
	public void setBaseFont(Font font) {
		baseFont = font;
		baseMetrics = getFontMetrics(font);
		metricsMap.clear();
	}

	/**
	 * Returns the current base font.
	 */
	public Font getBaseFont() {
		return baseFont;
	}

	/**
	 * Regenerates the fields for the sample text panel.
	 */
	public void updateDisplay() {
		setSelectedIndex(selectedIndex);
		fieldPanel.setBackgroundColor(BACKGROUND.getColor());
		genLayouts();
	}

	/**
	 * Builds the main panel.
	 */
	private void buildPanel() {
		setLayout(new BorderLayout());
		add(buildColorChooserPanel(), BorderLayout.CENTER);
		add(buildSelectionPanel(), BorderLayout.WEST);
	}

	/**
	 * Builds the color chooser panel.
	 */
	private JComponent buildColorChooserPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		colorChooser = new JColorChooser();
		colorChooser.setPreviewPanel(new JPanel()); // no preview panel

		panel.add(colorChooser, BorderLayout.NORTH);
		panel.add(buildPreviewPanel(), BorderLayout.CENTER);
		return panel;
	}

	/**
	 * Builds the field selection panel.
	 */
	private JComponent buildSelectionPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		namesList = new JList<>(elements);
		namesList.setVisibleRowCount(10);
		JScrollPane scrollPane = new JScrollPane(namesList);
		Border border = BorderFactory.createCompoundBorder(
			BorderFactory.createEmptyBorder(4, 4, 4, 4), BorderFactory.createEtchedBorder());
		scrollPane.setBorder(BorderFactory.createTitledBorder(border, "Screen Element"));
		panel.add(buildGlobalOptionsPanel(), BorderLayout.NORTH);
		panel.add(scrollPane, BorderLayout.CENTER);
		panel.add(buildElementOptionsPanel(), BorderLayout.SOUTH);
		return panel;
	}

	/**
	 * Builds the base font selection panel.
	 */
	private JPanel buildGlobalOptionsPanel() {
		Border border = BorderFactory.createCompoundBorder(
			BorderFactory.createEmptyBorder(4, 4, 4, 4), BorderFactory.createEtchedBorder());
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder(border, "Font"));

		JPanel panel1 = new JPanel(new FlowLayout());

		GraphicsEnvironment gEnv = GraphicsEnvironment.getLocalGraphicsEnvironment();
		String envfonts[] = gEnv.getAvailableFontFamilyNames();
		fontNameField = new GComboBox<>(envfonts);
		fontNameField.setBackground(Color.white);
		fontNameField.setRenderer(new FontRenderer());
		panel1.add(fontNameField);

		fontSizeField = new GComboBox<>(IntStream.rangeClosed(6, 32).boxed().toArray(Integer[]::new));
		fontSizeField.setBackground(Color.white);
		panel1.add(fontSizeField);
		panel.add(panel1, BorderLayout.NORTH);

		JPanel panel2 = new JPanel(new FlowLayout());
		JPanel subPanel = new JPanel(new GridLayout(1, 2, 2, 4));
		globalBoldCheckbox = new GCheckBox("Bold");
		globalItalicsCheckbox = new GCheckBox("Italics");
		subPanel.add(globalBoldCheckbox);
		subPanel.add(globalItalicsCheckbox);
		panel2.add(subPanel);
		panel.add(panel2, BorderLayout.SOUTH);
		return panel;

	}

	//Displays the font field with the actual fonts for easier selection
	class FontRenderer extends GDLabel implements ListCellRenderer<String> {
		private static final long serialVersionUID = 1L;
		private final Color SELECTED_COLOR = new Color(10, 36, 106);

		public FontRenderer() {
			setOpaque(true);
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends String> list, String value,
				int index, boolean isSelected, boolean cellHasFocus) {
			setText(value);
			Font origFont = fontNameField.getFont();
			setFont(new Font(value.toString(), origFont.getStyle(), origFont.getSize()));

			setBackground(isSelected ? SELECTED_COLOR : Color.white);
			setForeground(isSelected ? Color.white : Color.black);

			return this;
		}
	}

	/**
	 * Builds the selected Field options panel.
	 */
	private JPanel buildElementOptionsPanel() {
		Border border = BorderFactory.createCompoundBorder(
			BorderFactory.createEmptyBorder(4, 4, 4, 4), BorderFactory.createEtchedBorder());

		JPanel panel = new JPanel(new BorderLayout());

		JPanel subPanel = new JPanel(new GridLayout(1, 3, 2, 4));
		subPanel.setBorder(BorderFactory.createTitledBorder(border, "Style Settings"));
		boldCheckbox = new GCheckBox("Bold");
		italicsCheckbox = new GCheckBox("Italics");
		customCheckbox = new GCheckBox("Custom");
		subPanel.add(customCheckbox);
		subPanel.add(boldCheckbox);
		subPanel.add(italicsCheckbox);
		panel.add(subPanel, BorderLayout.SOUTH);

		subPanel = new JPanel(new BorderLayout());
		subPanel.setBorder(BorderFactory.createTitledBorder(border, "Color"));
		colorPanel = new JPanel();
		colorPanel.setBackground(Color.white);
		subPanel.add(colorPanel, BorderLayout.CENTER);
		panel.add(subPanel, BorderLayout.NORTH);
		return panel;
	}

	/**
	 * builds the preview panel.
	 */
	private JComponent buildPreviewPanel() {
		fieldPanel = new FieldPanel(new SimpleLayoutModel());
		IndexedScrollPane scroll = new IndexedScrollPane(fieldPanel);
		return scroll;
	}

	/**
	 * Generates the Fields for the preview panel.
	 */
	private void genLayouts() {
		maxWidth = 0;
		List<Layout> list = new ArrayList<>();

		LayoutBuilder lb = new LayoutBuilder(1);
		lb.add("     /***********************************/", COMMENT_PLATE);
		list.add(lb.getLayout());
		lb = new LayoutBuilder(1);
		lb.add("     /*             PLATE               */", COMMENT_PLATE);
		list.add(lb.getLayout());
		lb = new LayoutBuilder(1);
		lb.add("     /***********************************/", COMMENT_PLATE);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(1);
		lb.add("     Tags: tag1, tag2", FUN_TAG);
		lb.add("         ", null);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(1);
		lb.add("       ", null);
		lb.add("entry", ENTRY_POINT);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(5);
		lb.add("1000", ADDRESS);
		lb.add("         ", null);
		lb.add("c2 17 3d       ", BYTES);
		lb.add("call   ", MNEMONIC);
		lb.add("printf", LABELS_NON_PRIMARY);
		lb.add("         ", null);
		lb.add("; End of line comment ", COMMENT_EOL);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(5);
		lb.add("1003", ADDRESS);
		lb.add("         ", null);
		lb.add("23 15 3d       ", BYTES);
		lb.add("call   ", MNEMONIC_OVERRIDE);
		lb.add("0x10000", BAD_REF_ADDR);
		lb.add("        ", null);
		lb.add("; 0x10000 is not in memory ", COMMENT_EOL);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(7);
		lb.add("1006", ADDRESS);
		lb.add("         ", null);
		lb.add("b2 3f 2d       ", BYTES);
		lb.add("mov    ", MNEMONIC);
		lb.add("ax", REGISTERS, true);
		lb.add(",[", SEPARATOR, true);
		lb.add("LAB2000", LABELS_PRIMARY, true);
		lb.add("]", SEPARATOR, true);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(3);
		lb.add("       ", null);
		lb.add("LAB1009", LABELS_PRIMARY);
		lb.add("                                   ", null);
		lb.add("XREF[1,1]: 100c,", XREF);
		lb.add(" 1012", XREF_OFFCUT);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(5);
		lb.add("1009", ADDRESS);
		lb.add("         ", null);
		lb.add("c5 b2 32       ", BYTES);
		lb.add("call   ", MNEMONIC);
		lb.add("sprintf", LABELS_NON_PRIMARY);
		lb.add("        ", null);
		lb.add("; alias label ", COMMENT_EOL);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(4);
		lb.add("100c", ADDRESS);
		lb.add("         ", null);
		lb.add("24 4e ff       ", BYTES);
		lb.add("jnz    ", MNEMONIC);
		lb.add("LAB1009", LABELS_PRIMARY);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(8);
		lb.add("100f", ADDRESS);
		lb.add("         ", null);
		lb.add("23 35 d2       ", BYTES);
		lb.add("mov", MNEMONIC, true);
		lb.add("    ", MNEMONIC);
		lb.add("ax", REGISTERS);
		lb.add(",[", SEPARATOR);
		lb.add("dataAlias", LABELS_NON_PRIMARY);
		lb.add("]", SEPARATOR);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(4);
		lb.add("1012", ADDRESS);
		lb.add("         ", null);
		lb.add("22 f3 b2       ", BYTES);
		lb.add("jnz    ", MNEMONIC);
		lb.add("LAB1009+1", LABELS_NON_PRIMARY, true);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(4);
		lb.add("1016", ADDRESS);
		lb.add("         ", null);
		lb.add("c5 48 9d       ", BYTES);
		lb.add("call   ", MNEMONIC);
		lb.add("MyFunc", FUN_NAME);
		lb.add("        ", null);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(1);
		lb.add(".........", SEPARATOR);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(1);
		lb.add("       ", null);
		lb.add("sprintf", LABELS_NON_PRIMARY);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(2);
		lb.add("       ", null);
		lb.add("printf", ENTRY_POINT);
		lb.add("                                    ", null);
		lb.add("XREF[2,0]: 1000, 1009", XREF);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(7);
		lb.add("1500", ADDRESS);
		lb.add("         ", null);
		lb.add("23 35 d2       ", BYTES);
		lb.add("mov    ", MNEMONIC);
		lb.add("[", SEPARATOR);
		lb.add("DATA", LABELS_PRIMARY);
		lb.add("],", SEPARATOR);
		lb.add("0x73", CONSTANT);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(1);
		lb.add("//  This is a pre-comment", COMMENT_PRE);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(3);
		lb.add("1503", ADDRESS);
		lb.add("         ", null);
		lb.add("bc       ", BYTES);
		lb.add("ret    ", MNEMONIC);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(1);
		lb.add("//  This is a post-comment", COMMENT_POST);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(1);
		lb.add(".........", SEPARATOR);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(2);
		lb.add("       ", null);
		lb.add("LAB2000", LABELS_PRIMARY);
		lb.add("                                   ", null);
		lb.add("XREF[1,0]: 1006", XREF);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(4);
		lb.add("2000", ADDRESS);
		lb.add("         ", null);
		lb.add("24 4e          ", BYTES);
		lb.add("dw    ", MNEMONIC);
		lb.add("0x07", CONSTANT);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(1);
		lb.add("       ", null);
		lb.add("dataAlias", LABELS_NON_PRIMARY);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(2);
		lb.add("       ", null);
		lb.add("DATA", LABELS_PRIMARY);
		lb.add("                                      ", null);
		lb.add("XREF[2,0]: 100f, 1500", XREF);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(8);
		lb.add("2002", ADDRESS);
		lb.add("         ", null);
		lb.add("00 18 00 21    ", BYTES);
		lb.add("Struct Point    ", MNEMONIC);
		lb.add("(", SEPARATOR);
		lb.add("24", CONSTANT);
		lb.add(",", SEPARATOR);
		lb.add("33", CONSTANT);
		lb.add(")", SEPARATOR);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(2);
		lb.add("                            ", null);
		lb.add("X", FIELD_NAME);
		lb.add("    ", null);
		lb.add("24", CONSTANT);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(2);
		lb.add("                            ", null);
		lb.add("Y", FIELD_NAME);
		lb.add("    ", null);
		lb.add("33", CONSTANT);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(1);
		lb.add("       ", null);
		lb.add("//  This is a function comment", COMMENT_EOL);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(13);
		lb.add("       ", null);
		lb.add("Word ", FUN_RET_TYPE);
		lb.add("MyFunc ", FUN_NAME);
		lb.add("(", SEPARATOR);
		lb.add("DWord auto-x", FUN_AUTO_PARAMS);
		lb.add(", ", SEPARATOR);
		lb.add("DWord y", FUN_PARAMS);
		lb.add(", ", SEPARATOR);
		lb.add("DWord z", FUN_PARAMS);
		lb.add(", ", SEPARATOR);
		lb.add("Word n", FUN_PARAMS);
		lb.add(",", SEPARATOR);
		lb.add("Float delta", FUN_PARAMS);
		lb.add(")", SEPARATOR);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(1);
		lb.add("          ", null);
		lb.add("Call-Fixup: _MyFuncFixup ", FUN_CALL_FIXUP);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(3);
		lb.add("       ", null);
		lb.add("12    ", PARAMETER_DYNAMIC);
		lb.add("DWord  ", PARAMETER_DYNAMIC);
		lb.add("param_12  ", PARAMETER_DYNAMIC);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(3);
		lb.add("       ", null);
		lb.add("8    ", PARAMETER_CUSTOM);
		lb.add("DWord  ", PARAMETER_CUSTOM);
		lb.add("param_8  ", PARAMETER_CUSTOM);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(3);
		lb.add("       ", null);
		lb.add("4    ", PARAMETER_CUSTOM);
		lb.add("Word   ", PARAMETER_CUSTOM);
		lb.add("param_4  ", PARAMETER_CUSTOM);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(3);
		lb.add("       ", null);
		lb.add("-4   ", VARIABLE);
		lb.add("Float  ", VARIABLE);
		lb.add("local_4  ", VARIABLE);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(2);
		lb.add("       ", null);
		lb.add("MyFunc", LABELS_PRIMARY);
		lb.add("                                      ", null);
		lb.add("XREF[2,0]: 4e5a, d56e", XREF);
		list.add(lb.getLayout());

		lb = new LayoutBuilder(4);
		lb.add("2006", ADDRESS);
		lb.add("         ", null);
		lb.add("3a ef 43       ", BYTES);
		lb.add("mov    ", MNEMONIC);
		lb.add("DAT0000", BAD_REF_ADDR);
		lb.add("        ", null);
		list.add(lb.getLayout());

		layouts = new Layout[list.size()];
		list.toArray(layouts);

		if (modelListener != null) {
			modelListener.dataChanged(BigInteger.ZERO, BigInteger.valueOf(layouts.length));
		}
	}

	/**
	 * updates the style of the field at the selected index.
	 */
	private void updateStyle() {
		if (customCheckbox.isSelected()) {
			int style = Font.PLAIN;
			if (boldCheckbox.isSelected()) {
				style |= Font.BOLD;
			}
			if (italicsCheckbox.isSelected()) {
				style |= Font.ITALIC;
			}
			elements[selectedIndex].setStyle(style);
		}
		else {
			elements[selectedIndex].setStyle(-1);
		}
		setSelectedIndex(selectedIndex);
	}

	private FontMetrics getMetrics(int style) {
		Integer i = new Integer(style);
		FontMetrics fm = metricsMap.get(i);
		if (fm == null) {
			if (style == -1) {
				fm = getFontMetrics(baseFont);
				metricsMap.put(i, fm);
			}
			else {
				Font font = new Font(baseFont.getName(), style, baseFont.getSize());
				fm = getFontMetrics(font);
				metricsMap.put(i, fm);
			}
		}
		return fm;
	}

	/**
	 * Tells the optionsDialog to enable the apply button.
	 */
	private void enableApply() {
		propertyChangeListener.propertyChange(
			new PropertyChangeEvent(this, GhidraOptions.APPLY_ENABLED, null, Boolean.TRUE));
	}

	/**
	 * This listener will be notified when changes are made that need to be applied.
	 * @param listener The listener to be notified.
	 */
	void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		this.propertyChangeListener = listener;
	}

	/**
	 * updates all the fields to be based on the new base font.
	 */
	private void updateFonts() {
		String name = (String) fontNameField.getSelectedItem();
		int size = baseFont.getSize();
		try {
			size = (Integer) fontSizeField.getSelectedItem();
		}
		catch (Exception e) {
		}

		if (size < 6) {
			size = 6;
		}
		else if (size > 50) {
			size = 50;
		}

		int style = Font.PLAIN;
		if (globalBoldCheckbox.isSelected()) {
			style |= Font.BOLD;
		}
		if (globalItalicsCheckbox.isSelected()) {
			style |= Font.ITALIC;
		}
		setBaseFont(new Font(name, style, size));

		setSelectedIndex(selectedIndex);
	}

//==================================================================================================	
// Inner Classes
//==================================================================================================	

	/**
	 * Simple layoutModel to be used for the preview panel.
	 */
	class SimpleLayoutModel implements LayoutModel {
		@Override
		public boolean isUniform() {
			return false;
		}

		/**
		 * Returns a layout for the given index.
		 */
		public Layout getLayout(int index) {
			return layouts[index];
		}

		@Override
		public Layout getLayout(BigInteger index) {
			return layouts[index.intValue()];
		}

		@Override
		public void addLayoutModelListener(LayoutModelListener listener) {
			modelListener = listener;
		}

		@Override
		public void flushChanges() {
		}

		@Override
		public BigInteger getIndexAfter(BigInteger index) {
			int i = index.intValue() + 1;
			if (i >= layouts.length) {
				return null;
			}
			return BigInteger.valueOf(i);
		}

		@Override
		public BigInteger getIndexBefore(BigInteger index) {
			if (index.compareTo(BigInteger.ZERO) <= 0) {
				return null;
			}
			return index.subtract(BigInteger.ONE);
		}

		@Override
		public Dimension getPreferredViewSize() {
			return new Dimension(maxWidth, 500);
		}

		@Override
		public void removeLayoutModelListener(LayoutModelListener listener) {
			modelListener = null;
		}

		@Override
		public BigInteger getNumIndexes() {
			return BigInteger.valueOf(layouts.length);
		}

	}

	/**
	 * Class to create the layouts for the preview panel.
	 */
	class LayoutBuilder {
		private ClippingTextField[] fields;
		int startPos;
		int fieldNum;

		/**
		 * Constructor
		 * @param size the number of fields in the layout
		 */
		LayoutBuilder(int size) {

			fields = new ClippingTextField[size];
		}

		void add(String text, ScreenElement element) {
			add(text, element, false);
		}

		/**
		 * Adds the string and adorns it based on the given type (display index)
		 */
		void add(String text, ScreenElement element, boolean underline) {

			// add some padding to push off of the edge
			if (fieldNum == 0) {
				text = "    " + text;
			}

			if (element == null) {
				startPos += baseMetrics.stringWidth(text);
			}
			else {
				FontMetrics metrics = getMetrics(element.getStyle());
				int length = metrics.stringWidth(text);
				AttributedString as = new AttributedString(text, element.getColor(), metrics,
					underline, UNDERLINE.getColor());
				FieldElement field = new TextFieldElement(as, 0, 0);
				fields[fieldNum] =
					new ScreenElementTextField(element, startPos, length, field, hlFactory);
				fieldNum++;
				startPos += length;
				maxWidth = Math.max(maxWidth, startPos);
			}
		}

		/**
		 * Returns a layout consisting of all the added text fields.
		 */
		Layout getLayout() {
			return new SingleRowLayout(fields);
		}
	}

	private class ScreenElementTextField extends ClippingTextField {
		private ScreenElement screenElement;

		ScreenElementTextField(ScreenElement screenElement, int startX, int length,
				FieldElement field, HighlightFactory factory) {
			super(startX, length, field, factory);
			this.screenElement = screenElement;
		}

		ScreenElement getScreenElement() {
			return screenElement;
		}
	}
}
