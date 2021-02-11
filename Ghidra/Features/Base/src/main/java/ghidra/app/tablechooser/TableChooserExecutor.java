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

/**
 * The interface clients must implement to use the {@link TableChooserDialog}.  This class is the
 * callback that is used to process items from the dialog's table as users select one or more
 * rows in the table and then press the table's "apply" button.
 * 
 * <P>See the notes on {@link #useBulkTransaction()}.   We recommend you override that method to
 * return true.
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
	 * @param rowObject the AddressRowObject to be executed upon
	 * @return true if the rowObject should be removed from the table, false otherwise
	 */
	public boolean execute(AddressableRowObject rowObject);

	/**
	 * When true, the calls to {@link #execute(AddressableRowObject)} will be wrapped in a 
	 * transaction.  This allows clients to not use transactions themselves.   This can increase
	 * performance when the user selects a large number of rows in the table to be executed, as 
	 * this API will only use on transaction for all rows, instead of one per row.  
	 * 
	 * <P>When true, this will use one transaction per button press of the 
	 * {@link TableChooserDialog}.   Thus, if the user only processes a single row per button 
	 * press, then there is no performance gain over the traditional use of transactions.
	 * 
	 * <P><B>We recommend clients override this method to return true</B>.
	 * 
	 * <P>Note: when false is returned from this method, <b>no transaction is created before the
	 * call to {@link #execute(AddressableRowObject)}</b>--the client is responsible for 
	 * transaction management in this case.
	 * 
	 * <P>For backward compatibility, this method defaults to returning false.  You must override
	 * this method to return true in your code to make use of the single bulk transaction.
	 * 
	 * @return true to use bulk transactions; false to use no transaction at all when calling
	 *         {@link #execute(AddressableRowObject)}; default is false
	 */
	public default boolean useBulkTransaction() {
		return false;  // false by default for backward compatibility 
	}
}
