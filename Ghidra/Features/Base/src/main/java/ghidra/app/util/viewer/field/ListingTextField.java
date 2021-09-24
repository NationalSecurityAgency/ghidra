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

import java.awt.Graphics;
import java.awt.Rectangle;
import java.util.Arrays;
import java.util.List;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.EmptyProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;

/**
 * ListingField implementation for text fields.
 */
public class ListingTextField implements ListingField, TextField {

	private ProxyObj<?> proxy;
	private FieldFactory factory;
	protected TextField field;

	/**
	 * Creates a new ListingTextField that displays the text on a single line, clipping as needed.
	 * @param factory the field factory that generated this field
	 * @param proxy the object used to populate this field
	 * @param fieldElement the individual element within the field.
	 * This holds text, attributes and location information.
	 * @param startX the starting X position of the field
	 * @param width the width of the field
	 * @param provider the highlight provider.
	 * @return the text field.
	 */
	public static ListingTextField createSingleLineTextField(FieldFactory factory,
			ProxyObj<?> proxy, FieldElement fieldElement, int startX, int width,
			HighlightProvider provider) {

		HighlightFactory hlFactory =
			new FieldHighlightFactory(provider, factory.getClass(), proxy.getObject());
		TextField field = new ClippingTextField(startX, width, fieldElement, hlFactory);
		return new ListingTextField(factory, proxy, field);
	}

	public static ListingTextField createSingleLineTextFieldWithReverseClipping(
			AddressFieldFactory factory, ProxyObj<?> proxy, FieldElement fieldElement, int startX,
			int width, HighlightProvider provider) {
		HighlightFactory hlFactory =
			new FieldHighlightFactory(provider, factory.getClass(), proxy.getObject());
		TextField field = new ReverseClippingTextField(startX, width, fieldElement, hlFactory);
		return new ListingTextField(factory, proxy, field);
	}

	/**
	 * Displays the given text, word-wrapping as needed to avoid clipping (up to the max number of
	 * lines.)
	 * @param factory the field factory that generated this field
	 * @param proxy the object used to populate this field
	 * @param fieldElement the individual element within the field.
	 * This holds text, attributes and location information.
	 * @param startX the starting X position of the field
	 * @param width the width of the field
	 * @param maxLines the maxLines to display.
	 * @param provider the highlight provider.
	 * @return the text field.
	 */
	public static ListingTextField createWordWrappedTextField(FieldFactory factory,
			ProxyObj<?> proxy, FieldElement fieldElement, int startX, int width, int maxLines,
			HighlightProvider provider) {

		HighlightFactory hlFactory =
			new FieldHighlightFactory(provider, factory.getClass(), proxy.getObject());
		TextField field =
			new WrappingVerticalLayoutTextField(fieldElement, startX, width, maxLines, hlFactory);
		return new ListingTextField(factory, proxy, field);
	}

	/**
	 * Displays the list of text strings, packing as many as it can on a line before wrapping to
	 * the next line.
	 * @param factory the field factory that generated this field
	 * @param proxy the object used to populate this field
	 * @param textElements the array of elements for the field.
	 * Each of these holds text, attributes and location information.
	 * @param startX the starting X position of the field
	 * @param width the width of the field
	 * @param maxLines the maxLines to display.
	 * @param provider the highlight provider.
	 * @return the text field.
	 */
	public static ListingTextField createPackedTextField(FieldFactory factory, ProxyObj<?> proxy,
			FieldElement[] textElements, int startX, int width, int maxLines,
			HighlightProvider provider) {

		HighlightFactory hlFactory =
			new FieldHighlightFactory(provider, factory.getClass(), proxy.getObject());
		List<FieldElement> list = Arrays.asList(textElements);
		TextField field = new FlowLayoutTextField(list, startX, width, maxLines, hlFactory);
		return new ListingTextField(factory, proxy, field);
	}

	/**
	 * Displays the given array of text, each on its own line.
	 * @param factory the field factory that generated this field
	 * @param proxy the object used to populate this field
	 * @param textElements the array of elements for the field.
	 * Each of these holds text, attributes and location information.
	 * @param startX the starting X position of the field
	 * @param width the width of the field
	 * @param maxLines the maxLines to display.
	 * @param provider the highlight provider
	 * @return the text field.
	 */
	public static ListingTextField createMultilineTextField(FieldFactory factory, ProxyObj<?> proxy,
			FieldElement[] textElements, int startX, int width, int maxLines,
			HighlightProvider provider) {

		HighlightFactory hlFactory =
			new FieldHighlightFactory(provider, factory.getClass(), proxy.getObject());
		List<FieldElement> list = Arrays.asList(textElements);
		TextField field =
			new VerticalLayoutTextField(list, startX, width, maxLines, hlFactory);
		return new ListingTextField(factory, proxy, field);
	}

	protected ListingTextField(FieldFactory factory, ProxyObj<?> proxy, TextField field) {
		this.factory = factory;
		this.proxy = proxy;
		this.field = field;
	}

	@Override
	public void setPrimary(boolean b) {
		field.setPrimary(b);
	}

	@Override
	public RowColLocation dataToScreenLocation(int dataRow, int dataColumn) {
		return field.dataToScreenLocation(dataRow, dataColumn);
	}

	@Override
	public RowColLocation screenToDataLocation(int screenRow, int screenColumn) {
		return field.screenToDataLocation(screenRow, screenColumn);
	}

	@Override
	public int getWidth() {
		return field.getWidth();
	}

	@Override
	public int getPreferredWidth() {
		return field.getPreferredWidth();
	}

	@Override
	public int getHeight() {
		return field.getHeight();
	}

	@Override
	public int getHeightAbove() {
		return field.getHeightAbove();
	}

	@Override
	public int getHeightBelow() {
		return field.getHeightBelow();
	}

	@Override
	public int getStartX() {
		return field.getStartX();
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context,
			Rectangle clip, FieldBackgroundColorManager map, RowColLocation cursorLoc,
			int rowHeight) {
		field.paint(c, g, context, clip, map, cursorLoc, rowHeight);
	}

	@Override
	public boolean contains(int x, int y) {
		return field.contains(x, y);
	}

	@Override
	public int getNumDataRows() {
		return field.getNumDataRows();
	}

	@Override
	public int getNumRows() {
		return field.getNumRows();
	}

	@Override
	public int getNumCols(int row) {
		return field.getNumCols(row);
	}

	@Override
	public int getX(int row, int col) {
		return field.getX(row, col);
	}

	@Override
	public int getY(int row) {
		return field.getY(row);
	}

	@Override
	public int getRow(int y) {
		return field.getRow(y);
	}

	@Override
	public int getCol(int row, int x) {
		return field.getCol(row, x);
	}

	@Override
	public boolean isValid(int row, int col) {
		return field.isValid(row, col);
	}

	@Override
	public Rectangle getCursorBounds(int row, int col) {
		return field.getCursorBounds(row, col);
	}

	@Override
	public int getScrollableUnitIncrement(int topOfScreen, int direction, int max) {
		return field.getScrollableUnitIncrement(topOfScreen, direction, max);
	}

	@Override
	public boolean isPrimary() {
		return field.isPrimary();
	}

	@Override
	public void rowHeightChanged(int heightAbove, int heightBelow) {
		field.rowHeightChanged(heightAbove, heightBelow);
	}

	@Override
	public String getText() {
		return field.getText();
	}

	@Override
	public String getTextWithLineSeparators() {
		return field.getTextWithLineSeparators();
	}

	@Override
	public RowColLocation textOffsetToScreenLocation(int textOffset) {
		return field.textOffsetToScreenLocation(textOffset);
	}

	@Override
	public int screenLocationToTextOffset(int row, int col) {
		return field.screenLocationToTextOffset(row, col);
	}

	@Override
	public FieldFactory getFieldFactory() {
		return factory;
	}

	@Override
	public String toString() {
		return getText();
	}

	@Override
	public ProxyObj<?> getProxy() {
		if (proxy == null) {
			return EmptyProxy.EMPTY_PROXY;
		}
		return proxy;
	}

	@Override
	public FieldFormatModel getFieldModel() {
		return factory.getFieldModel();
	}

	@Override
	public boolean isClipped() {
		return field.isClipped();
	}

	@Override
	public Object getClickedObject(FieldLocation fieldLocation) {
		return getFieldElement(fieldLocation.row, fieldLocation.col);
	}

	@Override
	public FieldElement getFieldElement(int screenRow, int screenColumn) {
		return field.getFieldElement(screenRow, screenColumn);
	}

}
