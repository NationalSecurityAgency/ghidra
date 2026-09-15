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
package ghidra.framework.store;

/**
 * <code>UnknownFolderItem</code> corresponds to a folder item which has an unknown storage type 
 * or has encountered a storage failure.
 */
public interface UnknownFolderItem extends FolderItem {

	public static final String UNKNOWN_CONTENT_TYPE = "Unknown-File";

	/**
	 * Get the file type:
	 * <ul>
	 * <li>{@link FolderItem#DATABASE_FILE_TYPE}</li>
	 * <li>{@link FolderItem#DATAFILE_FILE_TYPE}</li>
	 * <li>{@link FolderItem#LINK_FILE_TYPE}</li>
	 * </ul>
	 * @return file type or {@link FolderItem#UNKNOWN_FILE_TYPE} (-1) if unknown
	 */
	public int getFileType();

}
