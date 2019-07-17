/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.misc;

import java.awt.*;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

import javax.swing.*;
import javax.swing.event.ChangeListener;
import javax.swing.text.*;

/**
 * 
 */
public class RegisterField extends JTextField {
//	private static Color UNSET_COLOR = new Color(204,0,204);
	private int bitSize;
	private Long currentValue;
	private long maxValue;
    private PlainDocument doc;
	private boolean inFocus;
	private boolean skipFilter;
	private ChangeListener listener;
	private Color noValueColor = Color.LIGHT_GRAY;
	private Color valueColor = Color.BLACK;
    private boolean useNoValue;
    /**
     * Constructor for RegisterField.
     */
    public RegisterField(int bitSize, Long initialValue) {
    	this(bitSize, initialValue, true);
    }
    
    public RegisterField(int bitSize, Long initialValue, boolean useNoValue) {
        this.useNoValue = useNoValue;
    	setBitSize( bitSize );
    	
    	doc = new PlainDocument();
    	doc.setDocumentFilter(new MyDocFilter());
    	this.setDocument(doc);
		doSetValue(initialValue);    	

    	this.addFocusListener(new FocusListener() {
            public void focusGained(FocusEvent ev) {
				inFocus = true;
				doSetValue(currentValue);
            }

            public void focusLost(FocusEvent ev) {
 				inFocus = false;
				doSetValue(currentValue);
            }
        });
    }
	public Long getValue() {
		return currentValue;
	}
	
	public void setNoValueColor(Color c) {
		noValueColor = c;
		updateColor();
	}
	public void setValueColor(Color c) {
		valueColor = c;
		updateColor();
	}
	private void updateColor() {
		if (inFocus || currentValue != null) {
			setForeground(valueColor);
			setHorizontalAlignment(LEFT);
		}
		else {
			setForeground(noValueColor);
			setHorizontalAlignment(CENTER);
		}
	}
    public void setBitSize( int bitSize ) {
        this.bitSize = bitSize;

        boolean isValid = bitSize >= 1 && bitSize < 64;

        this.setEditable(isValid);
        this.setEnabled(isValid);

        this.useNoValue = true;

        if (isValid) {
            this.maxValue = (1L << bitSize) - 1;
        }
        else {
            skipFilter = true;
            this.maxValue = 1;
        }

        /// if the value is no longer valid, then clear the value
        if ( !isValidValue( getValue() ) ) {
            doSetValue( null );
        }
    }
    public void setValue(Long value) {
		if (isEqual(value, currentValue)) {
			return;
		}
		doSetValue(value);
    }
    private void doSetValue(Long value) {
        if (value == null) {
            if (inFocus) {
				setTextField("");
            }
            else {
            	if (useNoValue) {
					setTextField("-- No Value --");
            	}
            	else {
            		setTextField("");
            	}
            }
        }
        else {
			setTextField("0x"+Long.toHexString(value.longValue()));
        }
        currentValue = value;
		updateColor();
    }
    private boolean isEqual(Long l1, Long l2) {
    	if (l1 != null) {
    		return l1.equals(l2);
    	}
    	else if (l2 != null) {
    		return false;
    	}
    	return true;
    }
	private void setTextField(String text) {
        if ( doc == null ) {
            return;
        }
		skipFilter = true;
        try {
            doc.replace(0, doc.getLength(), text, null);
        }
        catch (BadLocationException e) {}
		skipFilter = false;
	}
	public void setChangeListener(ChangeListener listener) {
		this.listener = listener;
	}
	private boolean processText() {
		String text = getText();
	
		if (text.length() == 0){
			if (currentValue != null) {
				currentValue = null;
				notifyListeners();
			}
			return true;
		}
		
		if (text.equals("0x") || text.equals("0X")) {
		 	if ((currentValue == null) || (currentValue.longValue() != 0)) {
				currentValue = new Long(0);
				notifyListeners();
			}
			return true;
		}
		try {
			if (!text.startsWith("0x") && !text.startsWith("0X")) {
				while(text.length() > 1 && text.charAt(0)== '0') {
					text = text.substring(1);
				}		
			}
			Long newValue = Long.decode(text);	
			if ( isValidValue( newValue ) ) {
				if (!newValue.equals(currentValue)) {
					currentValue = newValue;
					notifyListeners();
				}
				return true;
			}
		}
		catch(Exception e) {
		}
		Toolkit.getDefaultToolkit().beep();
		return false;
	}

    private boolean isValidValue(Long value) {
        if ( value == null ) {
            return false;
        }
        long l = value.longValue();
        return (l >= 0) && (l <= maxValue);
    }

    	
	class MyDocFilter extends DocumentFilter {
        /**
         * @see javax.swing.text.DocumentFilter#insertString(FilterBypass, int, String, AttributeSet)
         */
        @Override
        public void insertString(FilterBypass fb, int offset, String string,
         				AttributeSet attr) throws BadLocationException {
			if (skipFilter) {
				super.insertString(fb, offset, string, attr);
				return;
			}

			String oldText = getText();
			fb.insertString(offset, string, attr);	
			if (!processText()) {
				fb.replace(0, doc.getLength(), oldText, attr);
			}
        }

        /**
         * @see javax.swing.text.DocumentFilter#remove(FilterBypass, int, int)
         */
        @Override
        public void remove(FilterBypass fb, int offset, int length)
            throws BadLocationException {
			if (skipFilter) {
				super.remove(fb, offset, length);
				return;
			}

			String oldText = getText();
			fb.remove(offset, length);
			if (!processText()) {
				fb.replace(0, doc.getLength(), oldText, null);
			}
        }

        /**
         * @see javax.swing.text.DocumentFilter#replace(FilterBypass, int, int, String, AttributeSet)
         */
        @Override
        public void replace(FilterBypass fb, int offset, int length,
            		String text, AttributeSet attrs) throws BadLocationException {
			if (skipFilter) {
				super.replace(fb, offset, length, text, attrs);
				return;
			}
			String oldText = getText();
			fb.replace(offset, length, text, attrs);	
			if (!processText()) {
				fb.replace(0, doc.getLength(), oldText, attrs);
			}
        }
    }

	public static void main(String[] args) {
		JFrame f = new JFrame("Test");
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(new JTextField("123"), BorderLayout.SOUTH);
		RegisterField rf = new RegisterField(1, new Long(1));
		panel.add(rf, BorderLayout.CENTER);
		f.getContentPane().add(panel);
		f.pack();
		f.setVisible(true);
	}	
		
	private void notifyListeners() {
		if (listener != null) {
			listener.stateChanged( null );
		}
	}		    	
	public int getBitSize() {
		return bitSize;
	}
	public Color getValueColor() {
		return valueColor;
	}
}

	
