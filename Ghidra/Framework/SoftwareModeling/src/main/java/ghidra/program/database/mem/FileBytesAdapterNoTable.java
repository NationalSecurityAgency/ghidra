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
package ghidra.program.database.mem;

import java.io.InputStream;
import java.util.Collections;
import java.util.List;

import db.DBBuffer;
import db.DBHandle;

/**
 * Version of the FileBytesAdapter used to access older databases for read-only and upgrade purposes.
 */
class FileBytesAdapterNoTable extends FileBytesAdapter {

	public FileBytesAdapterNoTable(DBHandle handle) {
		super(handle);
	}

	@Override
	FileBytes createFileBytes(String filename, long offset, long size, InputStream is) {
		throw new UnsupportedOperationException();
	}

	@Override
	DBBuffer getBuffer(int i) {
		return null;
	}

	@Override
	List<FileBytes> getAllFileBytes() {
		return Collections.emptyList();
	}

	@Override
	void refresh() {
		// do nothing
	}

	@Override
	boolean deleteFileBytes(FileBytes fileBytes) {
		return false;
	}

}
