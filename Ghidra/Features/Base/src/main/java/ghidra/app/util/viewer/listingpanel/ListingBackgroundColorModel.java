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
package ghidra.app.util.viewer.listingpanel;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.BackgroundColorModel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.listing.Program;

/**
 * This interface extends the  {@link BackgroundColorModel}  exclusively for BackgroundColorModels used by
 * the ListingPanel.  The {@link BackgroundColorModel} is a general contract for dealing with
 * background colors in a {@link FieldPanel}.  ListingBackgroundColorModels require additional
 * information such as the {@link AddressIndexMap} and the program so that it translate the indexes
 * to specific addresses and look up information in the program.
 */
public interface ListingBackgroundColorModel extends BackgroundColorModel {

	/**
	 * Called when the {@link AddressIndexMap} or the {@link Program} changes.
	 *
	 * @param listingPanel the {@link ListingPanel} that changed and where the new {@link AddressIndexMap}
	 * and {@link Program} can be retrieved.
	 */
	public void modelDataChanged(ListingPanel listingPanel);
}
