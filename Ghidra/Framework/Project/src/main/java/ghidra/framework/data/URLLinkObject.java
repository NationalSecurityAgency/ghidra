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
import java.net.URL;

import javax.help.UnsupportedOperationException;

import db.DBHandle;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@code DomainObjectAdapterLink} object provides a Ghidra URL (see {@link GhidraURL}) wrapper
 * where the URL is intended to refer to a {@link DomainFile} within another local or remote
 * project/repository.  Link files which correspond to this type of {@link DomainObject} are
 * not intended to be modified and should be created or deleted.  A checkout may be used when
 * an offline copy is required but otherwise serves no purpose since a modification and checkin
 * is not supported. 
 */
public class URLLinkObject extends DomainObjectAdapterDB {

	// Use a reduced DB buffer size to reduce file size for minimal content.
	// This will allow a 4-KByte DB buffer file to hold a URL upto ~470 bytes long.
	// Longer URLs will rely on 1-KByte chained buffers which will increase file length.
	private static final int DB_BUFFER_SIZE = 1024;

	private URL url;

	/**
	 * Constructs a new link file object
	 * @param name link name
	 * @param ghidraUrl link URL
	 * @param consumer the object that is using this program.
	 * @throws IOException if there is an error accessing the database or invalid URL specified.
	 */
	public URLLinkObject(String name, URL ghidraUrl, Object consumer) throws IOException {
		super(new DBHandle(DB_BUFFER_SIZE), name, 500, consumer);
		metadata.put(LinkHandler.URL_METADATA_KEY, ghidraUrl.toString());
		updateMetadata();
	}

	/**
	 * Constructs a link file object from a DBHandle (read-only)
	 * @param dbh a handle to an open program database.
	 * @param consumer the object that keeping the program open.
	 * @throws IOException if an error accessing the database occurs.
	 */
	public URLLinkObject(DBHandle dbh, Object consumer) throws IOException {
		super(dbh, "Untitled", 500, consumer);
		loadMetadata();
		String urlText = metadata.get(LinkHandler.URL_METADATA_KEY);
		if (urlText == null) {
			throw new IOException("Null link object");
		}
		url = new URL(urlText);
	}

	@Override
	public String getDescription() {
		return "Link-File";
	}

	/**
	 * Get link URL
	 * @return link URL
	 */
	public URL getLink() {
		return url;
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
