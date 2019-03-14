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
package ghidra.app.plugin.core.datamgr.actions;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.Vector;

import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.data.AnnotationHandler;
import ghidra.util.HelpLocation;

/**
 * A simple dialog to select the language export type.
 */
class AnnotationHandlerDialog extends DialogComponentProvider {

	private GhidraComboBox<AnnotationHandler> handlerComboBox;
	private List<AnnotationHandler> handlerList;
	private AnnotationHandler handler;

	private boolean success;
		
	AnnotationHandlerDialog(List<AnnotationHandler> handlerList) {
		super("Export Format");
		this.handlerList = handlerList;
			
		addWorkPanel(create());
		addOKButton();
		addCancelButton();
		setOkEnabled(true);
		setHelpLocation(new HelpLocation(HelpTopics.DATA_MANAGER, "Export_To"));
        setRememberSize( false );

	}
	
	@Override
    protected void cancelCallback() {
		close();
	}

	@Override
    protected void okCallback() {
		Object [] objs = handlerComboBox.getSelectedObjects();
		if (objs != null && objs.length > 0) {
			handler = (AnnotationHandler) objs[0];
		}
		success = true;
		close();
	}

	JPanel create() {
		JPanel outerPanel = new JPanel(new BorderLayout());
		
		handlerComboBox = new GhidraComboBox<>(new Vector<AnnotationHandler>(handlerList));
		handlerComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okCallback();
			}
		});
		outerPanel.add(handlerComboBox, BorderLayout.NORTH);
		return outerPanel;
	}
	
	public AnnotationHandler getHandler() { return handler; }
	
	public boolean wasSuccessful()        { return success; }
}
