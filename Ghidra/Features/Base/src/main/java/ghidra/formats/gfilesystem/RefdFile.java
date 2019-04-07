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

import java.io.Closeable;
import java.io.IOException;

/**
 * A {@link GFile} along with a {@link FileSystemRef} to keep the filesystem pinned
 * in memory.
 * <p>
 * The caller is responsible for {@link #close() closing} this object, which releases
 * the FilesystemRef.
 */
public class RefdFile implements Closeable {
	public final FileSystemRef fsRef;
	public final GFile file;

	public RefdFile(FileSystemRef fsRef, GFile file) {
		this.fsRef = fsRef;
		this.file = file;
	}

	@Override
	public void close() throws IOException {
		fsRef.close();
	}

}
