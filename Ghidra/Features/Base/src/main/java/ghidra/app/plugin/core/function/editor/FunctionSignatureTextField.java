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
package ghidra.app.plugin.core.function.editor;

import static java.awt.Color.blue;
import static java.awt.Color.red;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.*;

import docking.actions.KeyBindingUtils;
import ghidra.util.Swing;

class FunctionSignatureTextField extends JTextPane {
	private static final String ENTER_ACTION_NAME = "ENTER";
	private static final String ESCAPE_ACTION_NAME = "ESCAPE";
	private static final String TAB_ACTION_NAME = "TAB";
	public static Color DEFAULT_COLOR = Color.black;
	public static Color PARAMETER_NAME_COLOR = new Color(155, 50, 155);
	public static Color FUNCTION_NAME_COLOR = blue;
	public static Color ERROR_NAME_COLOR = red;

	private StyledDocument doc;
	private SimpleAttributeSet paramNameAttributes;
	private SimpleAttributeSet functionNameAttributes;
	private SimpleAttributeSet defaultAttributes;
	private ActionListener actionListener;
	private ActionListener escapeListener;
	private ActionListener tabListener;
	private ChangeListener changeListener;
	private SimpleAttributeSet errorAttributes;

	FunctionSignatureTextField() {
		Font myFont = getFont();
		setFont(myFont.deriveFont(24.0f));
		doc = getStyledDocument();
		AttributeSet inputAttributes = getInputAttributes();

		paramNameAttributes = new SimpleAttributeSet(inputAttributes);
		StyleConstants.setForeground(paramNameAttributes, PARAMETER_NAME_COLOR);

		functionNameAttributes = new SimpleAttributeSet(inputAttributes);
		StyleConstants.setForeground(functionNameAttributes, FUNCTION_NAME_COLOR);

		errorAttributes = new SimpleAttributeSet(inputAttributes);
		StyleConstants.setForeground(errorAttributes, ERROR_NAME_COLOR);

		defaultAttributes = new SimpleAttributeSet(inputAttributes);
		StyleConstants.setForeground(defaultAttributes, DEFAULT_COLOR);
		doc.addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				updateColors();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				clearAttributes(e.getOffset(), e.getLength());
				updateColors();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				// do nothing
			}
		});

		// add enter processing to the TextPane
		Action enterAction = new AbstractAction(ENTER_ACTION_NAME) {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (actionListener != null) {
					actionListener.actionPerformed(e);
				}
			}
		};
		KeyStroke enter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0);
		KeyBindingUtils.registerAction(this, enter, enterAction, JComponent.WHEN_FOCUSED);
		KeyBindingUtils.registerAction(this, enter, enterAction, JComponent.WHEN_IN_FOCUSED_WINDOW);

		// add escape processing to the TextPane
		Action escapeAction = new AbstractAction(ESCAPE_ACTION_NAME) {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (escapeListener != null) {
					escapeListener.actionPerformed(e);
				}
			}
		};
		KeyStroke escape = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);
		KeyBindingUtils.registerAction(this, escape, escapeAction, JComponent.WHEN_FOCUSED);
		KeyBindingUtils.registerAction(this, escape, escapeAction,
			JComponent.WHEN_IN_FOCUSED_WINDOW);

		// add escape processing to the TextPane
		Action tabAction = new AbstractAction(TAB_ACTION_NAME) {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (tabListener != null) {
					tabListener.actionPerformed(e);
				}
			}
		};
		KeyStroke tab = KeyStroke.getKeyStroke(KeyEvent.VK_TAB, 0);
		KeyBindingUtils.registerAction(this, tab, tabAction, JComponent.WHEN_FOCUSED);
		KeyBindingUtils.registerAction(this, tab, tabAction, JComponent.WHEN_IN_FOCUSED_WINDOW);
	}

	void setActionListener(ActionListener listener) {
		this.actionListener = listener;
	}

	void setEscapeListener(ActionListener listener) {
		this.escapeListener = listener;
	}

	void setTabListener(ActionListener listener) {
		this.tabListener = listener;
	}

	private void updateColors() {
		Swing.runLater(() -> {
			String text = getText();
			List<ColorField> computeColors = computeColors(text);
			if (computeColors != null) {
				doc.setCharacterAttributes(0, text.length(), defaultAttributes, true);
				for (ColorField colorField : computeColors) {
					doc.setCharacterAttributes(colorField.start, colorField.length(),
						colorField.attributes, true);
				}
			}
			notifyChange();
		});
	}

	void clearAttributes(final int start, final int length) {
		Swing.runLater(() -> doc.setCharacterAttributes(start, length, defaultAttributes, true));
	}

	void notifyChange() {
		if (changeListener != null) {
			changeListener.stateChanged(new ChangeEvent(this));
		}
	}

	void setChangeListener(ChangeListener listener) {
		this.changeListener = listener;
	}

	List<ColorField> computeColors(String text) {
		List<ColorField> list = new ArrayList<>();
		int functionRightParenIndex = text.lastIndexOf(')');
		int functionLeftParenIndex = findMatchingLeftParenIndex(text, functionRightParenIndex);
		if (functionLeftParenIndex < 0) {
			return null;
		}
		List<Integer> paramStartStopIndexes =
			findParamStartStopindexes(text, functionLeftParenIndex, functionRightParenIndex);

		if (paramStartStopIndexes == null) {
			return null;
		}

		SubString substring = new SubString(text, 0, functionLeftParenIndex).trim();
		SubString functionName = getLastWord(substring);
		if (functionName == null) {
			return null;
		}

		list.add(
			new ColorField(functionName.getStart(), functionName.getEnd(), functionNameAttributes));
		for (int i = 0; i < paramStartStopIndexes.size() - 1; i++) {
			int start = paramStartStopIndexes.get(i) + 1;
			int end = paramStartStopIndexes.get(i + 1);
			SubString paramString = new SubString(text, start, end);
			paramString = paramString.trim();
			if (paramString.toString().equals("...")) {
				continue;
			}
			if (paramString.toString().equals("void")) {
				continue;
			}
			// check for empty param list
			if (paramString.length() == 0 && paramStartStopIndexes.size() == 2) {
				break;
			}
			SubString paramName = getLastWord(paramString);
			if (paramName == null) {
				break;
			}
			while (paramName.length() > 0 && paramName.charAt(0) == '*') {
				paramName = paramName.substring(1);

			}
			list.add(new ColorField(paramName.getStart(), paramName.getEnd(), paramNameAttributes));
		}
		return list;
	}

	private SubString getLastWord(SubString string) {
		int lastIndexOf = string.lastIndexOf(' ');
		if (lastIndexOf < 0) {
			return null;
		}
		return string.substring(lastIndexOf + 1);
	}

	private List<Integer> findParamStartStopindexes(String text, int startIndex, int endIndex) {
		List<Integer> commaIndexes = new ArrayList<>();
		int templateCount = 0;
		commaIndexes.add(startIndex);
		for (int i = startIndex + 1; i < endIndex; i++) {
			char c = text.charAt(i);
			if (c == '<') {
				templateCount++;
			}
			else if (c == '>') {
				templateCount--;
			}
			else if (c == ',' && templateCount == 0) {
				commaIndexes.add(i);
			}
		}
		if (templateCount != 0) {
			return null;
		}
		commaIndexes.add(endIndex);
		return commaIndexes;
	}

	private static class ColorField {
		int start;
		int end;
		AttributeSet attributes;

		ColorField(int start, int end, AttributeSet attributes) {
			this.start = start;
			this.end = end;
			this.attributes = attributes;
		}

		public int length() {
			return end - start;
		}
	}

	private int findMatchingLeftParenIndex(String text, int lastRightParenIndex) {
		int parenLevel = 1;
		for (int i = lastRightParenIndex - 1; i >= 0; i--) {
			char c = text.charAt(i);
			if (c == ')') {
				parenLevel++;
			}
			else if (c == '(') {
				parenLevel--;
				if (parenLevel == 0) {
					return i;
				}
			}
		}
		return -1;
	}

	public static void main(String[] args) {
		JFrame jFrame = new JFrame();
		jFrame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		FunctionSignatureTextField field = new FunctionSignatureTextField();
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		jFrame.getContentPane().add(panel);
		panel.add(field);
		jFrame.setSize(400, 200);
		jFrame.setVisible(true);
	}

	private class SubString {
		private String text;
		private int subStringStart;
		private int subStringEnd;

		SubString(String text, int start, int end) {
			this.text = text;
			this.subStringStart = start;
			this.subStringEnd = end;
		}

		public char charAt(int i) {
			return text.charAt(subStringStart + i);
		}

		public int length() {
			return subStringEnd - subStringStart;
		}

		public int getEnd() {
			return subStringEnd;
		}

		public int getStart() {
			return subStringStart;
		}

		public SubString substring(int start) {
			return new SubString(text, subStringStart + start, subStringEnd);
		}

		@Override
		public String toString() {
			return text.substring(subStringStart, subStringEnd);
		}

		public int lastIndexOf(char c) {
			for (int i = subStringEnd - 1; i >= subStringStart; i--) {
				if (text.charAt(i) == c) {
					return i - subStringStart;
				}
			}
			return -1;
		}

		public SubString trim() {
			int start = subStringStart;
			int end = subStringEnd;
			while (text.charAt(start) == ' ' && start < end) {
				start++;
			}
			while (text.charAt(end - 1) == ' ' && start < end) {
				end--;
			}

			if (start == subStringStart && end == subStringEnd) {
				return this;
			}
			return new SubString(text, start, end);
		}
	}

	void setError(final int position, final int length) {
		Swing.runLater(() -> doc.setCharacterAttributes(position, length, errorAttributes, true));
	}
}
