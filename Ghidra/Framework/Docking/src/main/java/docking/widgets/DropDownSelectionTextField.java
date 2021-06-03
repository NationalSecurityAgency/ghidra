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
package docking.widgets;

import javax.swing.DefaultListSelectionModel;
import javax.swing.ListSelectionModel;

/**
 * A text field that handles comparing text typed by the user to the list of objects
 * and then presenting potential matches in a drop down window.  This class differs from 
 * its parent in that it allows the user to select items from the popup list.
 * 
 * <P><b>Usage note:</b> Typically this text field will not be used directly, but will 
 * instead be used indirectly by way of an editor.
 * If this field is used directly, then the user should use <ins>{@link #setSelectedValue(Object)}</ins> and
 * <ins>{@link #getSelectedValue()}</ins> to get and set data on this field, rather than calling 
 * <del>{@link #setText(String)}</del> and <del>{@link #getText()}</del>.
 * 
 * <P>Usage notes:
 * 	<UL>
 * 		<LI>Pressing ENTER with the drop-down list open will select and item and close 
 * 			the list</LI>
 * 		<LI>Pressing ENTER with the drop-down list not showing will trigger an
 * 			editingStopped() event, signaling that the user has made a choice</LI>
 * 		<LI>Pressing ESCAPE with the drop-down list open will close the list</LI>
 * 		<LI>Pressing ESCAPE with the drop-down list not showing will trigger an 
 * 			editingCancelled() event, signaling that the user has cancelled editing</LI>
 *  </UL>
 * 
 * @param <T> The type of object that this model manipulates
 */
public class DropDownSelectionTextField<T> extends DropDownTextField<T> {

	public DropDownSelectionTextField(DropDownTextFieldDataModel<T> dataModel) {
		super(dataModel);
	}

	@Override
	protected ListSelectionModel createListSelectionModel() {
		DefaultListSelectionModel model = new DefaultListSelectionModel();
		model.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		return model;
	}

}
