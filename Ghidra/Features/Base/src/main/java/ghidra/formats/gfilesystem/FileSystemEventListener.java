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

/**
 * Events broadcast when a {@link GFileSystem} is closed or has a {@link FileSystemRef} change.
 */
public interface FileSystemEventListener {
	/**
	 * Called by GFilesystem's {@link GFileSystem#close()}, before any destructive changes
	 * are made to the filesystem instance.
	 *
	 * @param fs {@link GFileSystem} that is about to be closed.
	 */
	public void onFilesystemClose(GFileSystem fs);

	/**
	 * Called by {@link FileSystemRefManager} when a new {@link FileSystemRef} is created or
	 * released.
	 * @param fs {@link GFileSystem} that is being updated.
	 * @param refManager {@link FileSystemRefManager} that is tracking the modified GFileSystem.
	 */
	public void onFilesystemRefChange(GFileSystem fs, FileSystemRefManager refManager);
}
