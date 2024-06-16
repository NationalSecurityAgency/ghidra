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
package ghidra.app.tablechooser;

import java.util.List;

import ghidra.util.task.TaskMonitor;

/**
 * The interface clients must implement to use the {@link TableChooserDialog}.  This class is the
 * callback that is used to process items from the dialog's table as users select one or more
 * rows in the table and then press the table's "apply" button.
 */
public interface TableChooserExecutor {

	/**
	 * A short name suitable for display in the "apply" button that indicates what the "apply"
	 * action does.
	 * @return A short name suitable for display in the "apply" button that indicates what the "apply"
	 * action does.
	 */
	public String getButtonName();

	/**
	 * Applies this executors action to the given rowObject.  Return true if the given object
	 * should be removed from the table.
	 *
	 * <P>This method call will be wrapped in a transaction so the client does not have to do so.
	 * Multiple selected rows will all be processed in a single transaction.
	 *
	 * @param rowObject the AddressRowObject to be executed upon
	 * @return true if the rowObject should be removed from the table, false otherwise
	 */
	public boolean execute(AddressableRowObject rowObject);

	/**
	 * A callback that clients can choose to use instead of {@link #execute(AddressableRowObject)}.
	 * <p>
	 * To use this method, simply override it to perform work on each item passed in.  Due to
	 * supporting backward compatibility, clients still have to implement
	 * {@link #execute(AddressableRowObject)}.  When using
	 * {@link #executeInBulk(List, List, TaskMonitor)}, simply implement
	 * {@link #execute(AddressableRowObject)} as a do-nothing method.
	 * <p>
	 * You are responsible for checking the cancelled state of the task monitor by calling
	 * {@link TaskMonitor#isCancelled()}.  This allows long-running operations to be cancelled.  You
	 * should also call {@link TaskMonitor#incrementProgress(long)} as you process each item in
	 * order to show progress in the UI.
	 * <p>
	 * Note: the {@link #execute(AddressableRowObject)} method is only called with items that are
	 * still in the dialog's table model.  Some clients may programmatically manipulate the table
	 * model by removing row objects via the dialog's add/remove methods. The
	 * {@link #execute(AddressableRowObject)} method is only called for items that still exist in
	 * the model.  Contrastingly, this version of execute offers no such protection.  Thus, if you
	 * manipulate the table model yourself, you also need to ensure that any items you process in
	 * this method are still in the dialog.  To see if the item is still in the dialog, call
	 * {@link TableChooserDialog#contains(AddressableRowObject)}.
	 *
	 * @param rowObjects the objects to be processed
	 * @param deleted place any items to be removed from the table into this list
	 * @param monitor the task monitor
	 * @return true if you wish to execute items in bulk; always return true from this method if
	 * 	       you override it
	 */
	public default boolean executeInBulk(List<AddressableRowObject> rowObjects,
			List<AddressableRowObject> deleted, TaskMonitor monitor) {
		return false;
	}
}
