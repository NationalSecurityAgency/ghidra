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
package ghidra.framework.data;

import java.io.File;
import java.io.IOException;

import javax.help.UnsupportedOperationException;

import db.DBHandle;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link URLLinkObject} provides a link-file path/URL wrapper
 * where the path/URL is intended to refer to a {@link DomainFile} within a local or remote
 * project/repository.  Link files which correspond to this type of {@link DomainObject} are
 * not intended to be modified and should be created or deleted.  A checkout may be used when
 * an offline copy is required but otherwise serves no purpose since a modification and checkin
 * is not supported. 
 * <P>
 * NOTE: This exists for backward compatibility and is no longer used for storing newly created
 * link-files.
 */
public class URLLinkObject extends DomainObjectAdapterDB {

	private String linkPath;

	/**
	 * Constructs an existing link file object from a DBHandle (read-only)
	 * @param dbh a handle to an open program database.
	 * @param consumer the object that keeping the program open.
	 * @throws IOException if an error accessing the database occurs.
	 */
	URLLinkObject(DBHandle dbh, Object consumer) throws IOException {
		super(dbh, "Untitled", 500, consumer);
		loadMetadata();
		linkPath = metadata.get(LinkHandler.URL_METADATA_KEY);
		if (linkPath == null) {
			throw new IOException("Null link path/URL");
		}
	}

	@Override
	public String getDescription() {
		return "Link-File";
	}

	/**
	 * Get the stored link path/URL
	 * @return link path/URL
	 */
	public String getLinkPath() {
		return linkPath;
	}

	@Override
	public final boolean isChangeable() {
		return false;
	}

	@Override
	public final void saveToPackedFile(File outputFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

}
