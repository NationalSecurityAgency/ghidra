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
package ghidra.plugins.fsbrowser;

import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.plugin.importer.ProjectIndexService;

/**
 * Context given to a {@link FSBFileHandler} instance when being initialized.
 * 
 * @param plugin the FSB plugin 
 * @param fsbComponent the FSB component
 * @param fsService the fs service
 * @param projectIndex the project index
 */
public record FSBFileHandlerContext(FileSystemBrowserPlugin plugin,
		FSBComponentProvider fsbComponent, FileSystemService fsService,
		ProjectIndexService projectIndex) {}
