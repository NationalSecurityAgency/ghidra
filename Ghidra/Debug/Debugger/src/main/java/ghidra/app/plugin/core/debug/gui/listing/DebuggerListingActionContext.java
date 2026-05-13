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

import org.apache.commons.lang3.StringUtils;

import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.gui.action.DebuggerProgramLocationActionContext;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.program.TraceProgramView;

public class DebuggerListingActionContext extends ListingActionContext
		implements DebuggerProgramLocationActionContext {
	public DebuggerListingActionContext(DebuggerListingProvider provider) {
		super(provider, provider);
	}

	public DebuggerListingActionContext(DebuggerListingProvider provider,
			ProgramLocation location) {
		super(provider, provider, location);
	}

	public DebuggerListingActionContext(DebuggerListingProvider provider, ProgramLocation location,
			ProgramSelection selection, ProgramSelection highlight) {
		super(provider, provider, location.getProgram(), location, selection, highlight);
	}

	@Override
	public TraceProgramView getProgram() {
		return (TraceProgramView) super.getProgram();
	}

	@Override
	public boolean hasSelection() {
		CodeViewerProvider provider = (CodeViewerProvider) getComponentProvider();
		String textSelection = provider.getTextSelection();
		if (!StringUtils.isBlank(textSelection)) {
			return true;
		}

		return super.hasSelection();
	}

	/**
	 * Overridden to signal that this navigatable's program may not be the same as the globally 
	 * active program.  This is done to signal that this navigatable can supply default context.
	 * 
	 * @return false
	 */
	@Override
	public boolean isActiveProgram() {
		// The active program for the debugger listing is the on in the  'main listing'.  We cannot
		// use Navigatable.isConnected() here, since that always returns false for the debugger.
		DebuggerListingProvider dlp = (DebuggerListingProvider) getComponentProvider();
		return dlp.isMainListing();
	}
}
