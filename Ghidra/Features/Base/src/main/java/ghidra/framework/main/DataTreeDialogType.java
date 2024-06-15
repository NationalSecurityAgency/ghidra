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
package ghidra.framework.main;

/**
 * Types of ways to use a DataTreeDialog.
 */
public enum DataTreeDialogType {
	/**
	 * Dialog type for opening domain data files
	 */
	OPEN,
	/**
	 * Dialog type for saving domain data files
	 */
	SAVE,
	/**
	 * Dialog type for choosing a user folder
	 */
	CHOOSE_FOLDER,
	/**
	 * Dialog type for creating domain data files
	 */
	CREATE
}
