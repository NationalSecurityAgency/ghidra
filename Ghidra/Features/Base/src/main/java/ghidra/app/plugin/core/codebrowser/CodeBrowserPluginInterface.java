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
package ghidra.app.plugin.core.codebrowser;

import ghidra.app.services.ViewManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public interface CodeBrowserPluginInterface {

	public PluginTool getTool();

	public String getName();

	public boolean isDisposed();

	public void providerClosed(CodeViewerProvider provider);

	public void broadcastLocationChanged(CodeViewerProvider provider, ProgramLocation loc);

	public void broadcastSelectionChanged(CodeViewerProvider provider, ProgramSelection selection);

	public void broadcastHighlightChanged(CodeViewerProvider provider, ProgramSelection highlight);

	public ViewManagerService getViewManager(CodeViewerProvider provider);

	public CodeViewerProvider createNewDisconnectedProvider();
}
