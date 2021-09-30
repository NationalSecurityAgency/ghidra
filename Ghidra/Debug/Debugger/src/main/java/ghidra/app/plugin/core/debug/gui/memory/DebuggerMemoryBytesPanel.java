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

import ghidra.app.plugin.core.byteviewer.*;
import ghidra.app.plugin.core.format.DataFormatModel;

public class DebuggerMemoryBytesPanel extends ByteViewerPanel {
	private final DebuggerMemoryBytesProvider provider;

	public DebuggerMemoryBytesPanel(DebuggerMemoryBytesProvider provider) {
		super(provider);
		// TODO: Would rather not provide this reverse path
		this.provider = provider;
	}

	/**
	 * TODO: I don't care for this
	 */
	public DebuggerMemoryBytesProvider getProvider() {
		return provider;
	}

	@Override
	protected ByteViewerComponent newByteViewerComponent(DataFormatModel model) {
		return new DebuggerMemoryByteViewerComponent(this, new ByteViewerLayoutModel(), model,
			getBytesPerLine(), getFontMetrics());
	}
}
