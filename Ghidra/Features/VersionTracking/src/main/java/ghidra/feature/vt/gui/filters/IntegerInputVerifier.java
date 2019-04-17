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

public class IntegerInputVerifier extends InputVerifier {

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
            Integer intValue = ((Number) formatter.stringToValue(text)).intValue();
            if ( intValue.compareTo( 0 ) < 0 ) {
                // no negatives or values over 1
                return false;
            }

            return true;
        }
        catch ( ParseException e ) {
            return false;
        }
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
