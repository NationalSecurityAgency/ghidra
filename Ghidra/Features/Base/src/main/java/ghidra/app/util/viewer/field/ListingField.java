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
package ghidra.app.util.viewer.field;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;

/**
 * Interface that extends the Field interface to add addition information that
 * the browser needs from the fields.
 */
public interface ListingField extends Field {
    /**
     * Returns the FieldFactory that generated this Field
     */
	public FieldFactory getFieldFactory();
    /**
     * Returns the height above the imaginary base line used for alignment of
     * fields.
     */
	int getHeightAbove();
    /**
     * Returns the height below the imaginary base line used for alignment of
     * fields.
     */
	int getHeightBelow();

    /**
     * Returns the fieldModel that has the FieldFactory that generated this field.
     */
	public FieldFormatModel getFieldModel();

    /**
     * Returns the object that the fieldFactory used to generate the information
     * in this field.
     */
	public ProxyObj getProxy();
	
	/**
	 * Returns the object that was clicked on a Field for the given FieldLocation.  This may be the
	 * field itself or a lower-level entity, such as a FieldElement. 
	 * 
	 * @param fieldLocation The location that was clicked.
	 * @return the object that was clicked
	 */
	public Object getClickedObject( FieldLocation fieldLocation );
}
