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
package ghidra.app.plugin.core.hover;

import javax.swing.JComponent;
import javax.swing.JToolTip;

import ghidra.app.services.HoverService;
import ghidra.framework.plugintool.PluginTool;

/**
 * Base class for listing hover extensions.
 */
public abstract class AbstractHover implements HoverService {

	protected final PluginTool tool;
	protected boolean enabled;

	protected final int priority;

	protected AbstractHover(PluginTool tool, int priority) {
		this.tool = tool;
		this.priority = priority;
	}

	@Override
	public final int getPriority() {
		return priority;
	}

	@Override
	public final boolean hoverModeSelected() {
		return enabled;
	}

	protected boolean isValidTooltipContent(String content) {
		if (content == null || content.length() == 0) {
			return false;
		}
		return true;
	}

	protected JComponent createTooltipComponent(String content) {

		if (!isValidTooltipContent(content)) {
			return null;
		}

		JToolTip tt = new JToolTip();
		tt.setTipText(content);
		return tt;
	}

//==================================================================================================
// Stubbed Methods
//==================================================================================================

	@Override
	public void scroll(int amount) {
		// stubbed
	}

	@Override
	public void componentHidden() {
		// don't care
	}

	@Override
	public void componentShown() {
		// don't care
	}
}
