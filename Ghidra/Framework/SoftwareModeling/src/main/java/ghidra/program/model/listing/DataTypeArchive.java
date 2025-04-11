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
package ghidra.program.model.listing;

import java.util.Date;

import ghidra.program.model.data.DataTypeManagerDomainObject;
import ghidra.program.model.data.StandAloneDataTypeManager;

/**
 * This interface represents the main entry point into an object which
 * stores all information relating to a single data type archive.
 */
public interface DataTypeArchive extends DataTypeManagerDomainObject {

	/** Name of data type archive information property list */
	public static final String DATA_TYPE_ARCHIVE_INFO = "Data Type Archive Information";
	/** Name of data type archive settings property list */
	public static final String DATA_TYPE_ARCHIVE_SETTINGS = "Data Type Archive Settings";
	/** Name of date created property */
	public static final String DATE_CREATED = "Date Created";
	/** Name of ghidra version property */
	public static final String CREATED_WITH_GHIDRA_VERSION = "Created With Ghidra Version";
	/** A date from January 1, 1970 */
	public static final Date JANUARY_1_1970 = new Date(0);

	/**
	 * {@return the associated standalone data type manager.}
	 */
	@Override
	public StandAloneDataTypeManager getDataTypeManager();

	/**
	 * {@return the default pointer size as it may be stored within the data type archive.}
	 */
	public int getDefaultPointerSize();

	/**
	 * {@return the creation date of this data type archive or Jan 1, 1970 if unknown.}
	 */
	public Date getCreationDate();

	/**
	 * Get the data type archive changes since the last save as a set of addresses.
	 * @return set of changed addresses within program.
	 */
	public DataTypeArchiveChangeSet getChanges();

	/**
	 * Invalidates any caching in a data type archive.
	 * NOTE: Over-using this method can adversely affect system performance.
	 */
	public void invalidate();

}
