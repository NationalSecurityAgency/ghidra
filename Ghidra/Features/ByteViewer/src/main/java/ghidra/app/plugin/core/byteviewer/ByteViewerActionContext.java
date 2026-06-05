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
package ghidra.app.plugin.core.byteviewer;

import java.util.Set;

import ghidra.app.context.NavigatableActionContext;
import ghidra.program.model.listing.Function;

public class ByteViewerActionContext extends NavigatableActionContext {

	private ByteViewerComponent activeColumn;

	public ByteViewerActionContext(ProgramByteViewerComponentProvider provider) {
		this(provider, null);
	}

	public ByteViewerActionContext(ProgramByteViewerComponentProvider provider,
			ByteViewerComponent activeColumn) {
		super(provider, provider);
		this.activeColumn = activeColumn;
	}

	@Override
	public ByteViewerComponentProvider getComponentProvider() {
		return (ByteViewerComponentProvider) super.getComponentProvider();
	}

	public ByteViewerComponent getActiveColumn() {
		return activeColumn;
	}

	@Override
	public boolean hasFunctions() {
		return false; // the Byte Viewer doesn't work on functions
	}

	@Override
	public Set<Function> getFunctions() {
		return Set.of(); // the Byte Viewer doesn't work on functions
	}
}
