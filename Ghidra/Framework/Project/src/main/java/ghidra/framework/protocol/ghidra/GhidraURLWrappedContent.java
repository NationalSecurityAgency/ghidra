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
package ghidra.framework.protocol.ghidra;

import ghidra.framework.model.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.NotFoundException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * <code>GhidraURLWrappedContent</code> provides controlled access to a Ghidra folder/file
 * associated with a Ghidra URL.  It is important to note the issuance of this object does
 * not guarantee existence of the requested resource.  Any object obtained via the getContent
 * method must be released via the release method.  The following rules should be followed
 * when using domain folder and files obtained.
 * <ol>
 * <li>The getContent method may only be invoked once per consumer</li>
 * <li>The content must be released when no longer in-use, however it should not be released
 * until any derivative domain folders and files are no longer in use as well.</li>
 * <li>A read-only or immutable domain object may remain open while the associated domain 
 * file/folder is released.</li>
 * </ol>
 */
public class GhidraURLWrappedContent {

	private final GhidraURLConnection c;

	private List<Object> consumers = new ArrayList<Object>();

	private ProjectData projectData;
	private Object refObject;

	public GhidraURLWrappedContent(GhidraURLConnection c) {
		this.c = c;
	}

	private boolean containsConsumer(Object consumer) {
		for (Object obj : consumers) {
			if (obj == consumer) {
				return true;
			}
		}
		return false;
	}

	private void addConsumer(Object consumer) {
		if (containsConsumer(consumer)) {
			throw new RuntimeException("duplcate consumer");
		}
		consumers.add(consumer);
	}

	private void removeConsumer(Object consumer) {
		int cnt = consumers.size();
		for (int i = 0; i < cnt; i++) {
			if (consumers.get(i) == consumer) {
				consumers.remove(i);
				if (consumers.isEmpty()) {
					closeProjectData();
				}
				return;
			}
		}
		throw new RuntimeException("consumer not found");
	}

	private void closeProjectData() {
		// Local project data can only be closed once and is not handled here
		if (projectData instanceof TransientProjectData) {
			projectData.close();
		}
		projectData = null;
		refObject = null;
	}

	private DomainFolder getExplicitFolder(String folderPath) throws InvalidNameException,
			IOException {
		DomainFolder folder = projectData.getRootFolder();
		for (String name : folderPath.substring(1).split("/")) {
			DomainFolder subfolder = folder.getFolder(name);
			if (subfolder == null) {
				subfolder = folder.createFolder(name);
			}
			folder = subfolder;
		}
		return folder;
	}

	private void resolve() throws IOException, NotFoundException {

		if (projectData != null) {
			return;
		}

		projectData = c.getProjectData();

		String folderItemName = c.getFolderItemName();
		String folderPath = c.getFolderPath();

		// Obtain referenced folder
		DomainFolder folder = projectData.getFolder(folderPath);
		if (folder == null && folderItemName == null && !c.isReadOnly()) {

			// if an explicit folder path was specified
			try {
				folder = getExplicitFolder(folderPath);
			}
			catch (InvalidNameException e) {
				// TODO: URL folder path is invalid
				closeProjectData();
				throw new NotFoundException("URL specifies invalid path: " + folderPath);
			}
		}
		if (folder == null) {
			// TODO: URL location not found
			closeProjectData();
			throw new NotFoundException("URL specifies unknown path: " + folderPath);
		}

		if (folderItemName == null) {
			refObject = folder;
			return;
		}

		DomainFile df = folder.getFile(folderItemName);
		if (df != null) {
			refObject = df;
			return;
		}

		closeProjectData();
		throw new NotFoundException("URL specifies unknown path: " + folderPath);
	}

	/**
	 * Get the domain folder or file associated with the Ghidra URL.
	 * The consumer is responsible for releasing the content object via the release method 
	 * when it is no longer in use.
	 * @param consumer object which is responsible for releasing the content
	 * @return domain file or folder
	 * @throws IOException
	 * @throws NotFoundException if the Ghidra URL does no correspond to a folder or file
	 * within the Ghidra repository/project.
	 * @see #release(Object, Object)
	 */
	public synchronized Object getContent(Object consumer) throws IOException, NotFoundException {
		addConsumer(consumer);
		boolean success = false;
		try {
			resolve();
			success = true;
		}
		finally {
			if (!success || refObject == null) {
				removeConsumer(consumer);
			}
		}
		return refObject;
	}

	/**
	 * Indicates the content object previously obtained from this wrapper is
	 * no longer in-use and the underlying connection may be closed.  A read-only 
	 * or immutable domain object may remain open and in-use after its associated
	 * domain folder/file has been released. 
	 * @param content
	 * @param consumer
	 */
	public synchronized void release(Object content, Object consumer) {
		if (content == null || content != refObject) {
			throw new RuntimeException("Invalid content object specified");
		}
		removeConsumer(consumer);
	}

}
