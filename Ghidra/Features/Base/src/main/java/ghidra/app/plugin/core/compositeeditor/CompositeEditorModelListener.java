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
package ghidra.app.plugin.core.compositeeditor;


/**
 * Composite Editor Model change listener interface.
 * This extends the CompositeViewerModelListener, which has a method for
 * notifying when a composite's data changes in the model.
 * This adds notification methods for selection changes due to an edit
 * of the editor model.
 */
public interface CompositeEditorModelListener extends CompositeViewerModelListener {
    // Definitions of the types of state changes that can occur.
    public static final int COMPOSITE_MODIFIED = 1;
    public static final int COMPOSITE_UNMODIFIED = 2;
    public static final int COMPOSITE_LOADED = 3;
    public static final int NO_COMPOSITE_LOADED = 4;
    public static final int EDIT_STARTED = 5;
    public static final int EDIT_ENDED = 6;

	/**
	 * Called whenever the composite data type editor state changes for whether or not
	 * to show undefined bytes in the editor.
	 *
	 * @param showUndefinedBytes true if undefined bytes should be displayed in the editor
	 */
	public abstract void showUndefinedStateChanged(boolean showUndefinedBytes);

    /**
     * Called whenever the data composite edit state changes.
     * Examples:<BR>
     * Whether or not the composite being edited has been
     * modified from the original.<BR>
     * Whether or not a composite is loaded in the model.
     *
     * @param type the type of state change: COMPOSITE_MODIFIED, COMPOSITE_UNMODIFIED,
     * COMPOSITE_LOADED, NO_COMPOSITE_LOADED, EDIT_STARTED, EDIT_ENDED.
     */
	public abstract void compositeEditStateChanged(int type);

//    /**
//     * Called when the data type for one of our components changes.
//     * This means that any component that has this data type may have consumed
//     * undefined bytes which followed it. Therefore any change that has been
//     * started, but not finished yet, may not be allowable and should be
//     * cancelled.
//     * @param dt the data type that has changed.
//     */
//    public abstract void componentDataTypeChanged(DataType dt);
    
    /**
     * Called when the model wants to end cell editing that is in progress.
     * This is due to an attempt to modify the composite data type in the
     * editor while the model's field edit state indicates a field is being
     * edited. It is up to the application to determine whether to cancel or 
     * apply the field edits.
     */
	public abstract void endFieldEditing();
	
}
