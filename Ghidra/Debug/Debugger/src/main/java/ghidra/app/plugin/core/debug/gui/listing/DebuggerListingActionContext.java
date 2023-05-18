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
package ghidra.app.plugin.core.debug.gui.listing;

import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.gui.action.DebuggerProgramLocationActionContext;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.program.TraceProgramView;

public class DebuggerListingActionContext extends CodeViewerActionContext
		implements DebuggerProgramLocationActionContext {
	public DebuggerListingActionContext(CodeViewerProvider provider) {
		super(provider);
	}

	public DebuggerListingActionContext(CodeViewerProvider provider, ProgramLocation location) {
		super(provider, location);
	}

	@Override
	public TraceProgramView getProgram() {
		return (TraceProgramView) super.getProgram();
	}
}
