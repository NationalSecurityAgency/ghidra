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
package ghidra.app.plugin.core.function;

import ghidra.app.util.PluginConstants;
import ghidra.framework.plugintool.PluginTool;

import java.awt.BorderLayout;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

import javax.swing.*;

import docking.DialogComponentProvider;

abstract class CommentDialog extends DialogComponentProvider {
    private JTextArea commentsField;

    private boolean applyWasDone;
    private String origComments;

    protected FunctionPlugin plugin;

    CommentDialog(FunctionPlugin plugin) {
        // changed name
        super("Set Comment");
        addWorkPanel(createPanel());
        addListeners();

        addOKButton();
        addApplyButton();
        addCancelButton();
        this.plugin = plugin;
    }

    void showDialog(String comment) {
        applyWasDone = true;
        origComments = comment;

        commentsField.setText(origComments);
        if (origComments != null && origComments.length() > 0) {
            commentsField.selectAll();
        }
        PluginTool tool = plugin.getTool();
        tool.showDialog( this, tool.getComponentProvider( 
            PluginConstants.CODE_BROWSER ));
    }
    
    /////////////////////////////////////////////
    // *** GhidraDialog "callback" methods ***
    /////////////////////////////////////////////

    /**
     * Callback for the cancel button.
     */
    @Override
    protected void cancelCallback() {
        close();
    }

    /**
     * Callback for the OK button.
     */
    @Override
    protected void okCallback() {
        applyCallback();
        close();
    }

    /**
     * Callback for the Apply button.
     */
    @Override
    protected void applyCallback() {
        if (!applyWasDone) {
            // Apply was hit
            origComments = commentsField.getText();
            doApply(origComments);
            applyWasDone = true;
        }
    }
    
    abstract protected void doApply(String comment);

    ////////////////////////////////////////////////////////////////////
    // ** private methods **
    ////////////////////////////////////////////////////////////////////

    /**
     * Create the panel for the dialog.
     */
    private JPanel createPanel() {

        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());

        JPanel p = new JPanel();
        commentsField = new JTextArea(10, 50);
        commentsField.setLineWrap(true);
        commentsField.setWrapStyleWord(true);
        JScrollPane scrollP = new JScrollPane(commentsField);

        p.add(scrollP);
        panel.add(scrollP, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Add listeners to the radio buttons.
     */
    private void addListeners() {
        commentsField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                applyWasDone = false;
            }
        });
    }
}
