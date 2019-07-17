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
package ghidra.app.plugin.core.searchmem;

import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;
import ghidra.util.StringUtilities;

public class AsciiSearchFormat extends SearchFormat {
	private JLabel searchType;
	private JComboBox<Charset> encodingCB;
	private JCheckBox caseSensitiveCkB;
	private JCheckBox escapeSequencesCkB;
	private Charset[] supportedCharsets =
		{ StandardCharsets.US_ASCII, StandardCharsets.UTF_8, StandardCharsets.UTF_16 };

	public AsciiSearchFormat(ChangeListener listener) {
		super("String", listener);
	}

	@Override
	public String getToolTip() {
		return "Interpret value as a sequence of characters.";
	}

	@Override
	public JPanel getOptionsPanel() {
		ActionListener al = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				changeListener.stateChanged(new ChangeEvent(this));
			}
		};
		searchType = new GDLabel("Encoding: ");

		encodingCB = new GComboBox<>(supportedCharsets);
		encodingCB.setName("Encoding Options");
		encodingCB.setSelectedIndex(0);
		encodingCB.addActionListener(al);

		caseSensitiveCkB = new GCheckBox("Case Sensitive");
		caseSensitiveCkB.setToolTipText("Allows for case sensitive searching.");
		caseSensitiveCkB.addActionListener(al);

		escapeSequencesCkB = new GCheckBox("Escape Sequences");
		escapeSequencesCkB.setToolTipText(
			"Allows specifying control characters using escape sequences " +
				"(i.e., allows \\n to be searched for as a single line feed character).");
		escapeSequencesCkB.addActionListener(al);

		JPanel stringOptionsPanel = new JPanel();
		stringOptionsPanel.setLayout(new BoxLayout(stringOptionsPanel, BoxLayout.Y_AXIS));
		stringOptionsPanel.setBorder(new TitledBorder("Format Options"));
		JPanel encodingOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		encodingOptionsPanel.add(searchType);
		encodingOptionsPanel.add(encodingCB);
		stringOptionsPanel.add(encodingOptionsPanel);
		JPanel caseSensitivePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		caseSensitivePanel.add(caseSensitiveCkB);
		stringOptionsPanel.add(caseSensitivePanel);
		JPanel escapeSequencesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		escapeSequencesPanel.add(escapeSequencesCkB);
		stringOptionsPanel.add(escapeSequencesPanel);
		return stringOptionsPanel;
	}

	@Override
	public boolean usesEndieness() {
		return encodingCB.getSelectedItem() == StandardCharsets.UTF_16; // Only UTF-16 uses Endianness.
	}

	@Override
	public SearchData getSearchData(String input) {
		final byte MASK_BYTE = (byte) 0xdf;

		int inputLength = input.length();
		Charset encodingSelection = (Charset) encodingCB.getSelectedItem();
		if (encodingSelection == StandardCharsets.UTF_16) {
			encodingSelection =
				(isBigEndian) ? StandardCharsets.UTF_16BE : StandardCharsets.UTF_16LE;
		}

		//Escape sequences in the "input" are 2 Characters long.
		if (escapeSequencesCkB.isSelected() && inputLength >= 2) {
			input = StringUtilities.convertEscapeSequences(input);
		}
		byte[] byteArray = input.getBytes(encodingSelection);
		byte[] maskArray = new byte[byteArray.length];
		Arrays.fill(maskArray, (byte) 0xff);

		// Time to mask some bytes for case insensitive searching.
		if (!caseSensitiveCkB.isSelected()) {
			int i = 0;
			while (i < byteArray.length) {
				if (encodingSelection == StandardCharsets.US_ASCII &&
					Character.isLetter(byteArray[i])) {
					maskArray[i] = MASK_BYTE;
					i++;
				}
				else if (encodingSelection == StandardCharsets.UTF_8) {
					int numBytes = bytesPerCharUTF8(byteArray[i]);
					if (numBytes == 1 && Character.isLetter(byteArray[i])) {
						maskArray[i] = MASK_BYTE;
					}
					i += numBytes;
				}
				// Assumes UTF-16 will return 2 Bytes for each character.
				// 4-byte UTF-16 will never satisfy the below checks because
				// none of their bytes can ever be 0.
				else if (encodingSelection == StandardCharsets.UTF_16BE) {
					if (byteArray[i] == (byte) 0x0 && Character.isLetter(byteArray[i + 1])) { // Checks if ascii character.
						maskArray[i + 1] = MASK_BYTE;
					}
					i += 2;
				}
				else if (encodingSelection == StandardCharsets.UTF_16LE) {
					if (byteArray[i + 1] == (byte) 0x0 && Character.isLetter(byteArray[i])) { // Checks if ascii character.
						maskArray[i] = MASK_BYTE;
					}
					i += 2;
				}
				else {
					i++;
				}
			}
		}

		return SearchData.createSearchData(input, byteArray, maskArray);
	}

	private int bytesPerCharUTF8(byte zByte) {
		// This method is intended for UTF-8 encoding.
		// The first byte in a sequence of UTF-8 bytes can tell
		// us how many bytes make up a char.
		int offset = 1;
		// If the char is ascii, this loop will be skipped.
		while ((zByte & 0x80) != 0x00) {
			zByte <<= 1;
			offset++;
		}
		return offset;
	}
}
