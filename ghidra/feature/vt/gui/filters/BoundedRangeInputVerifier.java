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
package ghidra.feature.vt.gui.filters;

import java.awt.Toolkit;
import java.text.ParseException;

import javax.swing.*;
import javax.swing.JFormattedTextField.AbstractFormatter;

public class BoundedRangeInputVerifier extends InputVerifier {

    private final JFormattedTextField otherField;
    private final boolean isOtherFieldUpperRange;
    private final Number upperRangeValue;
    private final Number lowerRangeValue;

    public BoundedRangeInputVerifier( JFormattedTextField otherField, boolean isOtherFieldUpperRange, 
            Number upperRangeValue, Number lowerRangeValue ) {
        this.otherField = otherField;
        this.isOtherFieldUpperRange = isOtherFieldUpperRange;
        this.upperRangeValue = upperRangeValue;
        this.lowerRangeValue = lowerRangeValue;
    }

    @Override
    public boolean verify( JComponent input ) {
        if ( !(input instanceof JFormattedTextField) ) {
            return true;
        }

        JFormattedTextField ftf = (JFormattedTextField)input;
        AbstractFormatter formatter = ftf.getFormatter();
        if ( formatter == null ) {
            return true;
        }

        String text = ftf.getText();
        try {

            //
            // First, make sure we are within bounds
            // 
            Number number = (Number) formatter.stringToValue(text);
            if ( compareNumbers( number, upperRangeValue ) > 0 ||
                 compareNumbers( number, lowerRangeValue ) < 0 ) {
                // no values above or below our max
                return false;
            }

            // 
            // Second, don't let any value through that crosses our other field's range
            // 
            boolean result = false;
            Number otherNumber = (Number) otherField.getValue();
            if ( isOtherFieldUpperRange ) {
                // make sure our value is below the upper range value
                result = compareNumbers( number, otherNumber ) <= 0;
            }

            // make sure our value is above the lower range value
            else {
                result = compareNumbers( number, otherNumber ) >= 0;
            }

            return result;
        } catch (ParseException pe) {
            return false;
        }
    }
    
    private int compareNumbers( Number number, Number otherNumber ) {
        if ( number instanceof Double ) {
            Double double1 = (Double) number;
            Double double2 = (Double) otherNumber;
            return double1.compareTo( double2 );
        }
        else if ( number instanceof Long ) {
            Long long1 = (Long) number;
            Long long2 = (Long) otherNumber;
            return long1.compareTo( long2 );
        }
        else if ( number instanceof Integer ) {
            Long long1 = number.longValue();
            Long long2 = otherNumber.longValue();
            return long1.compareTo( long2 );
        }
        return 0;
    }

    /** Overridden to beep when the user tries to click out of the edited field when invalid */
    @Override
    public boolean shouldYieldFocus( JComponent input ) {
        boolean shouldYieldFocus = super.shouldYieldFocus( input );
        if ( !shouldYieldFocus ) {
            warn();
        }
        return shouldYieldFocus;
    }

    private void warn() {
        Toolkit.getDefaultToolkit().beep();
    }
}
