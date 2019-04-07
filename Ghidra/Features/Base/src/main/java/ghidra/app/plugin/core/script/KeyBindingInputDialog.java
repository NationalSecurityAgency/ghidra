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
package ghidra.app.plugin.core.script;

import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;
import ghidra.util.ReservedKeyBindings;

import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.KeyStroke;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.KeyEntryListener;
import docking.KeyEntryTextField;


class KeyBindingInputDialog extends DialogComponentProvider implements KeyEntryListener {
    private KeyEntryTextField kbField;
    private KeyStroke ks;
    private boolean isCancelled;

    KeyBindingInputDialog(Component parent, String scriptName, KeyStroke currentKeyStroke, Plugin plugin, HelpLocation help) {
        super("Assign Script Key Binding", true, true, true, false);

        JLabel label = new JLabel(scriptName);
        kbField = new KeyEntryTextField(20, this);
        kbField.setName("KEY_BINDING");
        kbField.setText( currentKeyStroke == null ? "" : KeyEntryTextField.parseKeyStroke(currentKeyStroke) );

        JPanel panel = new JPanel(new BorderLayout(10,10));
        panel.setBorder(BorderFactory.createEmptyBorder(10,10,10,10));
        panel.add(label, BorderLayout.NORTH);
        panel.add(kbField, BorderLayout.CENTER);

        addWorkPanel(panel);
        addOKButton();
        addCancelButton();
        setHelpLocation(help);

        DockingWindowManager.showDialog(parent, this);
    }

    @Override
    protected void okCallback() {
        if ( ks != null && ReservedKeyBindings.isReservedKeystroke( ks ) ) {
            setStatusText( kbField.getText() + " is a reserved keystroke" );
            return;
        }
        
        close();
    }

    @Override
    protected void cancelCallback() {
        super.cancelCallback();
        isCancelled = true;
    }

    boolean isCancelled() {
        return isCancelled;
    }

    /**
     * @see docking.KeyEntryListener#processEntry(javax.swing.KeyStroke)
     */
    public void processEntry(KeyStroke keyStroke) {
        ks = keyStroke;
    }

    KeyStroke getKeyStroke() {
        return ks;
    }
}
