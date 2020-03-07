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
package ghidra.app.util.datatype.microsoft;

/**
 * Holds options for the commands for creating new data structures.
 */
public class DataApplyOptions {

	private boolean followData = true;
	private boolean clearInstructions = false;
	private boolean clearDefinedData = true;
	private boolean createLabel = true;
	private boolean createFunction = true;
	private boolean createBookmarks = true;
	private boolean createComments = true;

	/**
	 * Creates an DataApplyOptions object with the default values.
	 */
	public DataApplyOptions() {
	}

	/**
	 * Copy constructor
	 * @param dataApplyOptions the data apply options to copy
	 */
	public DataApplyOptions(DataApplyOptions dataApplyOptions) {
		followData = dataApplyOptions.followData;
		clearInstructions = dataApplyOptions.clearInstructions;
		clearDefinedData = dataApplyOptions.clearDefinedData;
		createLabel = dataApplyOptions.createLabel;
		createFunction = dataApplyOptions.createFunction;
		createBookmarks = dataApplyOptions.createBookmarks;
		createComments = dataApplyOptions.createComments;
	}

	/**
	 * An option indicating whether or not to create data that is referred to by the data structure.
	 * <br>Default is true.
	 * @return true if structures should be created for referred to data.
	 */
	public boolean shouldFollowData() {
		return followData;
	}

	/**
	 * Sets whether or not to create follow on data that is referred to by the new structure.
	 * @param followData true indicates follow on data should be created.
	 */
	public void setFollowData(boolean followData) {
		this.followData = followData;
	}

	/**
	 * An option indicating whether or not to clear existing instructions in order to create 
	 * new data.
	 * <br>Default is false.
	 * @return true if existing instructions should be cleared to create the new data.
	 */
	public boolean shouldClearInstructions() {
		return clearInstructions;
	}

	/**
	 * Sets whether or not to clear existing instructions in order to create new data.
	 * @param clearInstructions true indicates existing instructions should be cleared to create 
	 * the new data.
	 */
	public void setClearInstructions(boolean clearInstructions) {
		this.clearInstructions = clearInstructions;
	}

	/**
	 * An option indicating whether or not to clear existing defined data in order to create 
	 * new data.
	 * <br>Default is false.
	 * @return true if existing defined data should be cleared to create the new data.
	 */
	public boolean shouldClearDefinedData() {
		return clearDefinedData;
	}

	/**
	 * Sets whether or not to clear existing defined data in order to create new data.
	 * @param clearDefinedData true indicates existing defined data should be cleared to create 
	 * the new data.
	 */
	public void setClearDefinedData(boolean clearDefinedData) {
		this.clearDefinedData = clearDefinedData;
	}

	/**
	 * An option indicating whether or not to create a label for the new data or for a 
	 * referred to data or function.
	 * <br>Default is true.
	 * @return true if a label should be created for this data or for referred to structures 
	 * and functions.
	 */
	public boolean shouldCreateLabel() {
		return createLabel;
	}

	/**
	 * Sets whether or not to create labels for follow on data or a function that is referred to 
	 * by the current new structure.
	 * @param createLabel true indicates a label should be created.
	 */
	public void setCreateLabel(boolean createLabel) {
		this.createLabel = createLabel;
	}

	/**
	 * An option indicating whether or not to disassemble and create a function that is referred
	 * to by your current structure.
	 * <br>Default is true.
	 * @return true if referred to functions should be created.
	 */
	public boolean shouldCreateFunction() {
		return createFunction;
	}

	/**
	 * Sets whether or not to disassemble and create a function that is referred to 
	 * by the current new structure.
	 * @param createFunction true indicates a function should be created.
	 */
	public void setCreateFunction(boolean createFunction) {
		this.createFunction = createFunction;
	}

	/**
	 * An option indicating whether or not to create bookmarks indicating any problems that
	 * occurred while creating the current structure or information associated with it.
	 * <br>Default is true.
	 * @return true if error bookmarks should be created.
	 */
	public boolean shouldCreateBookmarks() {
		return createBookmarks;
	}

	/**
	 * Sets whether or not to create bookmarks for problems encountered while trying to create
	 * an new structure or information associated with it.
	 * @param createBookmarks true indicates error bookmarks should be created.
	 */
	public void setCreateBookmarks(boolean createBookmarks) {
		this.createBookmarks = createBookmarks;
	}

	/**
	 * An option indicating whether or not to create comments indicating any problems that
	 * occurred while creating the data or information associated with it.
	 * <br>Default is true.
	 * @return true if error comments should be created.
	 */
	public boolean shouldCreateComments() {
		return createComments;
	}

	/**
	 * Sets whether or not to create comments for problems encountered while trying to create
	 * a new structure or information associated with it.
	 * @param createComments true indicates comments for the data should be created.
	 */
	public void setCreateComments(boolean createComments) {
		this.createComments = createComments;
	}
}
