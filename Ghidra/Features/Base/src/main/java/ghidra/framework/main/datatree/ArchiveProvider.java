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
package ghidra.framework.main.datatree;

import ghidra.app.plugin.core.datamgr.archive.Archive;

import java.util.List;

/**
 * An interface to be implemented by any class that can return a list of Archives.
 * For example, the tool's data type manager can return a list of archives within the project.
 */
public interface ArchiveProvider {

	public List<Archive> getArchives();
}
