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
package ghidra.framework.model;

import java.io.IOException;
import java.net.URL;
import java.util.List;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.User;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TestDummyProjectData implements ProjectData {

	@Override
	public Class<? extends LocalFileSystem> getLocalStorageClass() {
		// stub
		return null;
	}

	@Override
	public DomainFolder getRootFolder() {
		// stub
		return null;
	}

	@Override
	public DomainFolder getFolder(String path) {
		// stub
		return null;
	}

	@Override
	public int getFileCount() {
		// stub
		return 0;
	}

	@Override
	public DomainFile getFile(String path) {
		// stub
		return null;
	}

	@Override
	public void findOpenFiles(List<DomainFile> list) {
		// stub
	}

	@Override
	public DomainFile getFileByID(String fileID) {
		// stub
		return null;
	}

	@Override
	public URL getSharedFileURL(String path) {
		// stub
		return null;
	}

	@Override
	public String makeValidName(String name) {
		// stub
		return null;
	}

	@Override
	public ProjectLocator getProjectLocator() {
		// stub
		return null;
	}

	@Override
	public void addDomainFolderChangeListener(DomainFolderChangeListener listener) {
		// stub
	}

	@Override
	public void removeDomainFolderChangeListener(DomainFolderChangeListener listener) {
		// stub
	}

	@Override
	public void refresh(boolean force) throws IOException {
		// stub
	}

	@Override
	public User getUser() {
		// stub
		return null;
	}

	@Override
	public RepositoryAdapter getRepository() {
		// stub
		return null;
	}

	@Override
	public void convertProjectToShared(RepositoryAdapter repository, TaskMonitor monitor)
			throws IOException, CancelledException {
		// stub
	}

	@Override
	public void updateRepositoryInfo(RepositoryAdapter repository, TaskMonitor monitor)
			throws IOException, CancelledException {
		// stub
	}

	@Override
	public void close() {
		// stub
	}

	@Override
	public int getMaxNameLength() {
		// stub
		return 0;
	}

	@Override
	public void testValidName(String name, boolean isPath) throws InvalidNameException {
		// stub
	}

}
