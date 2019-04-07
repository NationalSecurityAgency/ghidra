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
package ghidra.feature.vt.gui.plugin;

import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.options.Options;

/**
 * Version tracking providers should implement this interface if they are interested in
 * being notified about version tracking state changes by the VTController.
 */
public interface VTControllerListener {

	public void sessionChanged(VTSession session);

	/**
	 * Indicates that the version tracking match that is selected has changed.
	 * @param matchInfo the matchInfo for the match that is now selected or null
	 * if no item is selected or multiple matches are selected.
	 */
	public void matchSelected(MatchInfo matchInfo);

	public void sessionUpdated(DomainObjectChangedEvent ev);

	/**
	 * Indicates that the version tracking mark-up item that is selected has changed.
	 * @param markupItem the mark-up item that is now selected or null
	 * if no item is selected or multiple mark-up items are selected.
	 */
	public void markupItemSelected(VTMarkupItem markupItem);

	public void optionsChanged(Options options);

	public void disposed();
}
