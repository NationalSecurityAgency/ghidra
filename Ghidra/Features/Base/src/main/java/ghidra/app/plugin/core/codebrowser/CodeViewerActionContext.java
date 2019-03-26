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
package ghidra.app.plugin.core.codebrowser;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.NavigatableRangeActionContext;
import ghidra.program.util.ProgramLocation;

public class CodeViewerActionContext extends ListingActionContext implements
		NavigatableRangeActionContext {

	public CodeViewerActionContext(CodeViewerProvider provider) {
		super(provider, provider);
	}

	public CodeViewerActionContext(CodeViewerProvider provider, ProgramLocation location) {
		super(provider, provider, location);
	}

	/**
	 * @return true if underlying code viewer corresponds to a dynamic listing
	 */
	public boolean isDyanmicListing() {
		return ((CodeViewerProvider) getComponentProvider()).isDynamicListing();
	}

}
