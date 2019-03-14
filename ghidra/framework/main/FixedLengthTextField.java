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
package ghidra.framework.main;

import java.awt.Dimension;
import java.awt.Insets;

import javax.swing.JComponent;
import javax.swing.JTextField;

/**
 * 
 * Text field that has a fixed length.
 * 
 * 
 */
class FixedLengthTextField extends JTextField {
    private JComponent sizeComponent;

    FixedLengthTextField(JComponent sizeComponent) {
        this("", sizeComponent);
    }

    FixedLengthTextField(String text, JComponent sizeComponent) {
        super(text);
        this.sizeComponent = sizeComponent;
    }

    /**
     * override parent method to line up the text field with the
     * scroll paths list in upper panel
     */
    @Override
    public Dimension getPreferredSize() {
        Insets insets = sizeComponent.getInsets();
        Dimension textSize = new Dimension(sizeComponent.getWidth()-insets.left,
                                           super.getPreferredSize().height);
        setPreferredSize(textSize);
        setSize(textSize);
        return textSize;
    }
}
