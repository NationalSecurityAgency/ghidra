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
package ghidra.framework.protocol.ghidra;

import java.net.URL;

public class RepositoryInfo {

	final URL repositoryURL;
	final String repositoryName;
	final boolean readOnly;

	public RepositoryInfo(URL repositoryURL, String repositoryName, boolean readOnly) {
		this.repositoryURL = repositoryURL;
		this.repositoryName = repositoryName;
		this.readOnly = readOnly;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof RepositoryInfo)) {
			return false;
		}
		RepositoryInfo other = (RepositoryInfo) obj;
		return readOnly == other.readOnly && repositoryURL.equals(other.repositoryURL);
	}

	@Override
	public int hashCode() {
		return repositoryURL.hashCode() ^ (readOnly ? 0 : 1);
	}

	@Override
	public String toString() {
		return repositoryURL.toExternalForm() + (readOnly ? "(read-only)" : "");
	}

	public String toShortString() {
		return repositoryName + (readOnly ? "(read-only)" : "");
	}
}
