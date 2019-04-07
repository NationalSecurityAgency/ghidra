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

import java.awt.Rectangle;
import java.awt.event.MouseEvent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.plugin.core.hover.AbstractHoverProvider;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.program.util.ProgramLocation;

public class ListingHoverProvider extends AbstractHoverProvider {

	public ListingHoverProvider() {
		super("ListingHoverProvider");
	}

	public void addHoverService(ListingHoverService hoverService) {
		super.addHoverService(hoverService);
	}

	public void removeHoverService(ListingHoverService hoverService) {
		super.removeHoverService(hoverService);
	}

	@Override
	protected ProgramLocation getHoverLocation(FieldLocation fieldLocation, Field field,
			Rectangle fieldBounds, MouseEvent event) {

		ProgramLocation loc = null;
		if (field instanceof ListingField) {
			ListingField listingField = (ListingField) field;
			loc = listingField.getFieldFactory().getProgramLocation(fieldLocation.getRow(),
				fieldLocation.getCol(), listingField);
		}

		return loc;
	}

}
