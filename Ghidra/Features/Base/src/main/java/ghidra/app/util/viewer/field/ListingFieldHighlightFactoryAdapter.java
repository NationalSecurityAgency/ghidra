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
package ghidra.app.util.viewer.field;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldHighlightFactory;
import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

/**
 * Wrapper class to translate calls to {@link FieldHighlightFactory} into a call needed by the 
 * {@link ListingHighlightProvider}.   This class holds field factory information in the text 
 * field to be provided to the highlightProvider to get highlights just before the field is painted.
 * <p>
 * This class is needed to allow the basic {@link Field} API to be used with more richness at the
 * {@link ListingPanel} level.
 */
public class ListingFieldHighlightFactoryAdapter implements FieldHighlightFactory {

	private ListingHighlightProvider provider;
	private ListingField listingField;

	/**
	 * Constructor
	 * @param provider the HighlightProvider that will actually compute the highlights.
	 */
	public ListingFieldHighlightFactoryAdapter(ListingHighlightProvider provider) {
		this.provider = provider;
	}

	void setListingField(ListingField listingField) {
		this.listingField = listingField;
	}

	@Override
	public Highlight[] createHighlights(Field field, String text, int cursorTextOffset) {
		if (listingField == null) {
			Msg.error(this,
				"Listing highlight factory not correctly setup; ListingField must be set",
				ReflectionUtilities.createJavaFilteredThrowable());
			return NO_HIGHLIGHTS;
		}
		return provider.createHighlights(text, listingField, cursorTextOffset);
	}
}
