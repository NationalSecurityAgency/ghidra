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
package ghidra.program.util;

import static ghidra.program.util.ProgramEvent.*;

/**
 * Interface to define event types and the method to generate an
 * event within Program.
 */
public interface DataTypeArchiveChangeManager {

	////////////////////////////////////////////////////////////////////////////
	//
	//            Deprecated data type archive event types
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * Category was added.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CATEGORY_ADDED = DATA_TYPE_CATEGORY_ADDED;

	/**
	 * Category was removed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CATEGORY_REMOVED = DATA_TYPE_CATEGORY_REMOVED;

	/**
	 * Category was renamed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CATEGORY_RENAMED = DATA_TYPE_CATEGORY_RENAMED;

	/**
	 * Category was moved.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_CATEGORY_MOVED = DATA_TYPE_CATEGORY_MOVED;

	/**
	 * Data type was added to a category.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_ADDED = DATA_TYPE_ADDED;

	/**
	 * Data type was removed from a category.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_REMOVED = DATA_TYPE_REMOVED;

	/**
	 * Data Type was renamed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_RENAMED = DATA_TYPE_RENAMED;

	/**
	 * Data type was moved to another category.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_MOVED = DATA_TYPE_MOVED;

	/**
	 * Data type was updated.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_CHANGED = DATA_TYPE_CHANGED;

	/**
	 * The settings on a data type were updated.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_SETTING_CHANGED = DATA_TYPE_SETTING_CHANGED;

	/**
	 * Data type was replaced in a category.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final ProgramEvent DOCR_DATA_TYPE_REPLACED = DATA_TYPE_REPLACED;

}
