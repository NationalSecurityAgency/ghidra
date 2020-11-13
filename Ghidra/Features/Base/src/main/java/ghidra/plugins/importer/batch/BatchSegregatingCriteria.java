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
package ghidra.plugins.importer.batch;

import java.util.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;

/**
 * Set of identifying pieces of info that allow us to segregate files that we are
 * importing into groups.
 * <p>
 * Criteria are:
 * <ul>
 * <li>Filename extension of source file</li>
 * <li>Loader name</li>
 * <li>Set of LanguageCompilerSpecs and preferred flags (ie. {@link BatchGroupLoadSpec})</li>
 * </ul>
 */
public class BatchSegregatingCriteria {

	private final Set<BatchGroupLoadSpec> groupLoadSpecs = new HashSet<>();
	private final String fileExt;
	private final String loader;

	public BatchSegregatingCriteria(Loader loader, Collection<LoadSpec> loadSpecs,
			ByteProvider provider) {
		for (LoadSpec loadSpec : loadSpecs) {
			groupLoadSpecs.add(new BatchGroupLoadSpec(loadSpec));
		}
		this.loader = loader.getName();
		fileExt = FilenameUtils.getExtension(loader.getPreferredFileName(provider));
	}

	public String getFileExt() {
		return fileExt;
	}

	public String getLoader() {
		return loader;
	}

	/**
	 * Return the {@link BatchGroupLoadSpec}s as a sorted list.
	 *
	 * @return sorted list of {@link BatchGroupLoadSpec}s.
	 */
	public List<BatchGroupLoadSpec> getBatchGroupLoadSpecs() {
		List<BatchGroupLoadSpec> result = new ArrayList<>(groupLoadSpecs);
		Collections.sort(result);
		return result;
	}

	public BatchGroupLoadSpec getFirstPreferredLoadSpec() {
		for (BatchGroupLoadSpec groupLoadSpec : groupLoadSpecs) {
			if (groupLoadSpec.preferred) {
				return groupLoadSpec;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return "[ext: " + (fileExt != null ? fileExt : "") + ", loader: " + loader +
			", load specs: " + groupLoadSpecs.toString() + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((fileExt == null) ? 0 : fileExt.hashCode());
		result = prime * result + ((loader == null) ? 0 : loader.hashCode());
		result = prime * result + ((groupLoadSpecs == null) ? 0 : groupLoadSpecs.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof BatchSegregatingCriteria)) {
			return false;
		}
		BatchSegregatingCriteria other = (BatchSegregatingCriteria) obj;
		if (fileExt == null) {
			if (other.fileExt != null) {
				return false;
			}
		}
		else if (!fileExt.equals(other.fileExt)) {
			return false;
		}
		if (loader == null) {
			if (other.loader != null) {
				return false;
			}
		}
		else if (!loader.equals(other.loader)) {
			return false;
		}
		if (groupLoadSpecs == null) {
			if (other.groupLoadSpecs != null) {
				return false;
			}
		}
		else if (!groupLoadSpecs.equals(other.groupLoadSpecs)) {
			return false;
		}
		return true;
	}
}
