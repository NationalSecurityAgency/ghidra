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
package ghidra.app.plugin.core.debug.gui.memory;

import static ghidra.lifecycle.Unfinished.TODO;

import ghidra.app.plugin.core.byteviewer.ByteViewerPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.framework.plugintool.PluginTool;

public class DebuggerMemoryBytesPlugin /*extends Plugin*/ {

	/**
	 * TODO: This will likely require a refactor of the existing {@link ByteViewerPlugin} to provide
	 * an abstract one that we can inherit from, in the same vein as the
	 * {@link DebuggerListingPlugin}.
	 */
	protected DebuggerMemoryBytesPlugin(PluginTool tool) {
		//super(tool);
		TODO();
	}
}
