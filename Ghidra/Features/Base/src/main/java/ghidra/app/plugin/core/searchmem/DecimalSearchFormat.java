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

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.button.GRadioButton;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;

public class DecimalSearchFormat extends SearchFormat {

	private static final String MINUS_SIGN = "-";
	private static final int BYTE = 0;
	private static final int WORD = 1;
	private static final int DWORD = 2;
	private static final int QWORD = 3;
	private static final int FLOAT = 4;
	private static final int DOUBLE = 5;

	private int decimalFormat = WORD;

	public DecimalSearchFormat(ChangeListener listener) {
		super("Decimal", listener);
	}

	@Override
	public String getToolTip() {
		return HTMLUtilities.toHTML(
			"Interpret values as a sequence of\n" + "decimal numbers, separated by spaces");
	}

	private void setDecimalFormat(int format) {
		decimalFormat = format;
		changeListener.stateChanged(new ChangeEvent(this));
	}

	@Override
	public JPanel getOptionsPanel() {
		ButtonGroup decimalGroup = new ButtonGroup();

		GRadioButton decimalByte = new GRadioButton("Byte", false);
		GRadioButton decimalWord = new GRadioButton("Word", true);
		GRadioButton decimalDWord = new GRadioButton("DWord", false);
		GRadioButton decimalQWord = new GRadioButton("QWord", false);
		GRadioButton decimalFloat = new GRadioButton("Float", false);
		GRadioButton decimalDouble = new GRadioButton("Double", false);

		decimalByte.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ev) {
				setDecimalFormat(BYTE);
			}
		});
		decimalWord.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ev) {
				setDecimalFormat(WORD);
			}
		});
		decimalDWord.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ev) {
				setDecimalFormat(DWORD);
			}
		});
		decimalQWord.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ev) {
				setDecimalFormat(QWORD);
			}
		});
		decimalFloat.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ev) {
				setDecimalFormat(FLOAT);
			}
		});
		decimalDouble.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ev) {
				setDecimalFormat(DOUBLE);
			}
		});

		decimalGroup.add(decimalByte);
		decimalGroup.add(decimalWord);
		decimalGroup.add(decimalDWord);
		decimalGroup.add(decimalQWord);
		decimalGroup.add(decimalFloat);
		decimalGroup.add(decimalDouble);

		JPanel decimalOptionsPanel = new JPanel();
		decimalOptionsPanel.setLayout(new GridLayout(3, 2));
		decimalOptionsPanel.add(decimalByte);
		decimalOptionsPanel.add(decimalWord);
		decimalOptionsPanel.add(decimalDWord);
		decimalOptionsPanel.add(decimalQWord);
		decimalOptionsPanel.add(decimalFloat);
		decimalOptionsPanel.add(decimalDouble);
		decimalOptionsPanel.setBorder(BorderFactory.createTitledBorder("Format Options"));

		return decimalOptionsPanel;

	}

	@Override
	public SearchData getSearchData(String input) {
		List<Byte> bytesList = new ArrayList<>();
		StringTokenizer tokenizer = new StringTokenizer(input);
		while (tokenizer.hasMoreTokens()) {
			String tok = tokenizer.nextToken();
			if (tok.equals(MINUS_SIGN)) {
				if (!input.endsWith(MINUS_SIGN)) {
					return SearchData.createInvalidInputSearchData("Cannot have space after a '-'");
				}
				return SearchData.createIncompleteSearchData("");
			}
			try {
				bytesList.addAll(getBytes(tok));
			}
			catch (NumberFormatException ex) {
				return SearchData.createInvalidInputSearchData("");
			}
			catch (RuntimeException re) {
				return SearchData.createInvalidInputSearchData(re.getMessage());
			}
		}
		return SearchData.createSearchData(input, getDataBytes(bytesList), null);
	}

	private byte[] getDataBytes(List<Byte> bytesList) {
		byte[] bytes = new byte[bytesList.size()];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (bytesList.get(i)).byteValue();
		}
		return bytes;
	}

	private List<Byte> getBytes(long value, int n) {
		List<Byte> list = new ArrayList<>();

		for (int i = 0; i < n; i++) {
			byte b = (byte) value;
			list.add(new Byte(b));
			value >>= 8;
		}
		if (isBigEndian) {
			Collections.reverse(list);
		}
		return list;
	}

	private void checkValue(long value, long min, long max) {
		if (value < min || value > max) {
			// I know, icky
			throw new RuntimeException("Number must be in the range [" + min + "," + max + "]");
		}
	}

	private List<Byte> getBytes(String tok) {
		switch (decimalFormat) {
			case BYTE:
				long value = Short.parseShort(tok);
				checkValue(value, Byte.MIN_VALUE, 255);
				return getBytes(value, 1);
			case WORD:
				value = Integer.parseInt(tok);
				checkValue(value, Short.MIN_VALUE, 65535);
				return getBytes(value, 2);
			case DWORD:
				value = Long.parseLong(tok);
				checkValue(value, Integer.MIN_VALUE, 4294967295l);
				return getBytes(value, 4);
			case QWORD:
				value = Long.parseLong(tok);
				return getBytes(value, 8);
			case FLOAT:
				tok = preProcessFloat(tok);
				float floatValue = Float.parseFloat(tok);
				value = Float.floatToIntBits(floatValue);
				return getBytes(value, 4);
			case DOUBLE:
				tok = preProcessFloat(tok);
				double dvalue = Double.parseDouble(tok);
				value = Double.doubleToLongBits(dvalue);
				return getBytes(value, 8);
			default:
				throw new AssertException("Unexpected format type");
		}
	}

	/**
	 * Checks for parsable characters that we don't want to allow (dDfF) and removes
	 * the start of an exponent expression (example 2.34e would become 2.34. So woudl 2.34-)
	 * @param the string that will be parsed into a float or double
	 * @return the parsable string
	 * @exception NumberFormatException thrown if the the tok contains any of "dDfF".
	 */
	private String preProcessFloat(String tok) {
		if ((tok.indexOf('d') >= 0) || (tok.indexOf('D') >= 0) || (tok.indexOf('F') >= 0) ||
			(tok.indexOf('f') >= 0)) {
			throw new NumberFormatException();
		}
		if (tok.endsWith("E") || tok.endsWith("e")) {
			tok = tok.substring(0, tok.length() - 1);
		}
		if (tok.endsWith("E-") || tok.endsWith("e-")) {
			tok = tok.substring(0, tok.length() - 2);
		}

		return tok;
	}

}
