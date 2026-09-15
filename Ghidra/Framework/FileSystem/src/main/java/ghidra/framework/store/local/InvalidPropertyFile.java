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
package ghidra.framework.store.local;

import java.io.File;
import java.io.IOException;

/**
 * {@link InvalidPropertyFile} provides a substitue {@link ItemPropertyFile} when one
 * fails to parse.  This allows the item's existance to be managed even if the item cannot
 * be opened.
 */
public class InvalidPropertyFile extends ItemPropertyFile {

	/**
	 * Construct an invalid property file instance if it previously failed to parse.
	 * @param dir native directory where this file is stored
	 * @param storageName stored property file name (without extension)
	 * @param parentPath logical parent path for the associated item
	 * @param name name of the associated item
	 * @throws IOException (never thrown since file is never read)
	 */
	public InvalidPropertyFile(File dir, String storageName, String parentPath, String name)
			throws IOException {
		super(dir, storageName, parentPath, name);
		// NOTE: IOException is prevented by having a do-nothing readState method below
	}

	@Override
	public final void readState() {
		// avoid potential parse failure
	}

}
