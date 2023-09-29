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
package ghidra.formats.gfilesystem;

import java.util.Comparator;
import java.util.List;

/**
 * Default implementation of base file system functionality.
 * 
 * @param <METADATATYPE> the type of objects that will be stored in the FileSystemIndexHelper
 */
public abstract class AbstractFileSystem<METADATATYPE> implements GFileSystem {
	protected final FileSystemService fsService;
	protected final FSRLRoot fsFSRL;
	protected FileSystemIndexHelper<METADATATYPE> fsIndex;
	protected FileSystemRefManager refManager = new FileSystemRefManager(this);

	/**
	 * Initializes the fields for this abstract implementation of a file system.
	 * 
	 * @param fsFSRL {@link FSRLRoot} of this file system
	 * @param fsService reference to the {@link FileSystemService} instance
	 */
	protected AbstractFileSystem(FSRLRoot fsFSRL, FileSystemService fsService) {
		this.fsService = fsService;
		this.fsFSRL = fsFSRL;
		this.fsIndex = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	protected Comparator<String> getFilenameComparator() {
		return null; // null will cause exact matches in the fsIndex.lookup()
	}

	@Override
	public GFile lookup(String path) {
		return fsIndex.lookup(null, path, getFilenameComparator());
	}

	@Override
	public List<GFile> getListing(GFile directory) {
		return fsIndex.getListing(directory);
	}

	@Override
	public int getFileCount() {
		return fsIndex.getFileCount();
	}

}
