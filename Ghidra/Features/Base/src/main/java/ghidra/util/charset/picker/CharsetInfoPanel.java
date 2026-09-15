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
package ghidra.util.charset.picker;

import java.awt.Font;
import java.lang.Character.UnicodeScript;
import java.util.*;

import javax.swing.*;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import docking.widgets.list.GListCellRenderer;
import generic.theme.Gui;
import ghidra.app.plugin.core.strings.CharacterScriptUtils;
import ghidra.util.charset.CharsetInfo;
import ghidra.util.layout.VariableHeightPairLayout;

/**
 * A JPanel that displays the details about a {@link CharsetInfo} object.
 */
public class CharsetInfoPanel extends JPanel {
	private Map<UnicodeScript, String> scriptExampleStrings = new HashMap<>();
	private JTextField nameTF;
	private JTextArea commentTA;
	private GCheckBox fixedCB;
	private JTextField minmaxTF;
	private JTextField alignTF;
	private JList<UnicodeScript> scriptsList;

	public CharsetInfoPanel() {
		super(new VariableHeightPairLayout());

		build();
	}

	private void build() {

		nameTF = new JTextField();
		nameTF.setEditable(false);
		nameTF.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		add(newLabel("Name:", "Charset name", nameTF, false));
		add(nameTF);

		commentTA = new JTextArea(2, 100);
		commentTA.setEditable(false);
		commentTA.setLineWrap(true);
		commentTA.setWrapStyleWord(true);
		Gui.registerFont(commentTA, "font.textarea.astextfield");

		add(newLabel("Description:", "Charset description", commentTA, true));
		add(commentTA);

		fixedCB = new GCheckBox();
		fixedCB.setEnabled(false);

		add(newLabel("Fixed Length:", "Charset uses a fixed number of bytes to produce a character",
			fixedCB, false));
		add(fixedCB);

		minmaxTF = new JTextField();
		minmaxTF.setEditable(false);
		minmaxTF.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		add(newLabel("Min/Max Bytes Per Char:",
			"Number of bytes a charset needs to produce a character", minmaxTF, false));
		add(minmaxTF);

		alignTF = new JTextField();
		alignTF.setEditable(false);
		alignTF.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		add(newLabel("Aligned Size:", "Byte offset that is valid to start a character", alignTF,
			false));
		add(alignTF);

		scriptsList = new JList<>(List.of().toArray(UnicodeScript[]::new));
		scriptsList.setCellRenderer(
			GListCellRenderer.createDefaultTextRenderer(this::getScriptCellRendererText));
		scriptsList.setVisibleRowCount(5);
		JScrollPane scriptsSP = new JScrollPane();
		scriptsSP.setFocusable(false);
		scriptsSP.getVerticalScrollBar().setFocusable(false);
		scriptsSP.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		scriptsSP.getViewport().add(scriptsList);

		add(newLabel("Scripts:", "The scripts that this charset produce", scriptsSP, true));
		add(scriptsSP);
	}

	private GLabel newLabel(String text, String tooltip, JComponent comp, boolean top) {
		GLabel label = new GLabel(text);
		if (top) {
		label.setVerticalAlignment(SwingConstants.TOP);
		}
		label.setToolTipText(tooltip);
		label.setLabelFor(comp);
		return label;
	}

	@Override
	public void setFont(Font font) {
		super.setFont(font);
		if (scriptExampleStrings != null) {
			scriptExampleStrings.clear();
		}
	}

	public void setCharset(CharsetInfo csi) {
		nameTF.setText(csi.getName());
		nameTF.setCaretPosition(0);
		commentTA.setText(csi.getComment());
		commentTA.setCaretPosition(0);
		fixedCB.setSelected(csi.hasFixedLengthChars());

		String min =
			csi.getMinBytesPerChar() > 0 ? Integer.toString(csi.getMinBytesPerChar()) : "unknown";
		String max =
			csi.getMaxBytesPerChar() > 0 ? Integer.toString(csi.getMaxBytesPerChar()) : "unknown";
		minmaxTF.setText("%s / %s".formatted(min, max));
		minmaxTF.setCaretPosition(0);

		alignTF.setText("%d".formatted(csi.getAlignment()));
		alignTF.setCaretPosition(0);

		scriptsList.setListData(List.copyOf(csi.getScripts()).toArray(UnicodeScript[]::new));
	}

	private String getScriptCellRendererText(UnicodeScript script) {
		buildScriptExamplesMap(getFont());
		if (script == null) {
			return "";
		}
		String name = script.name();
		String example = scriptExampleStrings.getOrDefault(script, "");
		if (!example.isEmpty()) {
			example = " \u2014 " + example;
		}
		return name + example;
	}

	private void buildScriptExamplesMap(Font f) {
		if (scriptExampleStrings.isEmpty()) {
			scriptExampleStrings.putAll(CharacterScriptUtils.getDisplayableScriptExamples(f, 7));
		}
	}
}
