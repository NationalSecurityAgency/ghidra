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

import java.awt.Color;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.Highlight;
import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.proxy.ProxyObj;

public class ErrorListingField extends ListingTextField {

	private static Color BG_ERROR_COLOR = new GColor("color.bg.listing.error");

	private Throwable t;

	private static ListingHighlightProvider myProvider =
		(text, field, cursorTextOffset) -> new Highlight[] {
			new Highlight(0, text.length() - 1, BG_ERROR_COLOR) };

	public ErrorListingField(FieldFactory ff, ProxyObj<?> proxy, int varWidth, Throwable t) {
		super(ff, proxy, null, createHighlightFactory());
		this.t = t;
		this.field = createField(ff, proxy, varWidth);
	}

	private static ListingFieldHighlightFactoryAdapter createHighlightFactory() {
		return new ListingFieldHighlightFactoryAdapter(myProvider);
	}

	private ClippingTextField createField(FieldFactory ff, ProxyObj<?> proxy, int varWidth) {
		ClippingTextField textField = new ClippingTextField(ff.getStartX() + varWidth,
			ff.getWidth(), createElement(ff, t), hlFactory);
		return textField;
	}

	private static FieldElement createElement(FieldFactory ff, Throwable t) {
		String message = t.getMessage() == null ? t.toString() : t.getMessage();
		AttributedString as =
			new AttributedString("*Error*: " + message + ".  Double click for Details.",
				Colors.FOREGROUND, ff.getMetrics());
		return new TextFieldElement(as, 0, 0);
	}

	public Throwable getThrowable() {
		return t;
	}

	@Override
	public Object getClickedObject(FieldLocation fieldLocation) {
		// overridden to return this object, rather than the lower-level text field
		return this;
	}
}
