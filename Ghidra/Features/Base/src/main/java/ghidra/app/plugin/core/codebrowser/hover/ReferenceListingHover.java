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
package ghidra.app.plugin.core.codebrowser.hover;

import ghidra.GhidraOptions;
import ghidra.app.plugin.core.hover.AbstractReferenceHover;
import ghidra.app.services.CodeFormatService;
import ghidra.framework.plugintool.PluginTool;

public class ReferenceListingHover extends AbstractReferenceHover implements ListingHoverService {

	private static final String NAME = "Reference Code Viewer";

	private static final String DESCRIPTION =
		"Shows \"referred to\" code and data within the listing.";

	private final static int PRIORITY = 50;

	public ReferenceListingHover(PluginTool tool) {
		this(tool, null);
	}

	public ReferenceListingHover(PluginTool tool, CodeFormatService codeFormatSvc) {
		super(tool, codeFormatSvc, PRIORITY);
	}

	@Override
	protected String getName() {
		return NAME;
	}

	@Override
	protected String getDescription() {
		return DESCRIPTION;
	}

	@Override
	protected String getOptionsCategory() {
		return GhidraOptions.CATEGORY_BROWSER_POPUPS;
	}

}
