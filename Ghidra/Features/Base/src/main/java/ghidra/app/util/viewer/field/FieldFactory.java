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

import java.awt.*;
import java.math.BigInteger;

import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.Gui;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.template.TemplateSimplifier;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Data;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL FIELDFACTORY CLASSES MUST END IN "FieldFactory".  If not,
 * the ClassSearcher will not find them.
 *
 * Base class for Field Factories.
 */
public abstract class FieldFactory implements ExtensionPoint {
	public static final String FONT_OPTION_NAME = "BASE FONT";
	public static final String BASE_LISTING_FONT_ID = "font.listing.base";

	protected FieldFormatModel model;
	protected String name;
	protected int startX;
	protected int width;
	private FontMetrics defaultMetrics;
	private FontMetrics[] fontMetrics = new FontMetrics[4];
	protected Font baseFont;
	protected int style = -1;
	protected boolean enabled = true;
	protected ListingHighlightProvider hlProvider;

	protected String colorOptionName;
	protected String styleOptionName;
	private TemplateSimplifier templateSimplifier;

	/**
	 * Base constructor
	 * @param name the name of the field
	 * @param model the model that the field belongs to.
	 * @param highlightProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	protected FieldFactory(String name, FieldFormatModel model,
			ListingHighlightProvider highlightProvider,
			Options displayOptions, Options fieldOptions) {
		this.name = name;
		this.model = model;
		this.hlProvider = highlightProvider;
		colorOptionName = name + " Color";
		styleOptionName = name + " Style";

		width = 100;
		templateSimplifier = model.getFormatManager().getTemplateSimplifier();
		initDisplayOptions(displayOptions);
		initFieldOptions(fieldOptions);
	}

	protected void initFieldOptions(Options fieldOptions) {
		fieldOptions.getOptions(name)
				.setOptionsHelpLocation(new HelpLocation("CodeBrowserPlugin", name));
	}

	protected void initDisplayOptions(Options displayOptions) {
		baseFont = Gui.getFont(BASE_LISTING_FONT_ID);
		// For most fields (defined in optionsGui) these will be set. But "ad hoc" fields won't,
		// so register something.  A second registration won't change the original

		displayOptions.registerOption(styleOptionName, -1, null, "Sets the " + style);

		style = displayOptions.getInt(styleOptionName, -1);
		setMetrics(baseFont);
	}

	/**
	 * Constructs a FieldFactory with given name.  Used only as potential field.
	 * @param name the name of the field.
	 */
	public FieldFactory(String name) {
		this.name = name;
	}

	/**
	 * Notification the services changed. Subclasses should override this method
	 * if they care about service changes.
	 */
	public void servicesChanged() {
		// for subclasses
	}

	/**
	 * Returns a new instance of this FieldFactory that can be used to generate fields
	 * instead of being used as a prototype.
	 * @param formatModel the model that the field belongs to.
	 * @param highlightProvider the HightLightProvider.
	 * @param options the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 * @return the factory
	 */
	public abstract FieldFactory newInstance(FieldFormatModel formatModel,
			ListingHighlightProvider highlightProvider, ToolOptions options,
			ToolOptions fieldOptions);

	/**
	 * Notifications that the display options changed.
	 * @param options the Display Options object that changed.
	 * @param optionName the name of the property that changed.
	 * @param oldValue the old value of the property.
	 * @param newValue the new value of the property.
	 */
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(FONT_OPTION_NAME)) {
			baseFont = SystemUtilities.adjustForFontSizeOverride((Font) newValue);
			setMetrics(baseFont);
		}
		else if (optionName.equals(styleOptionName)) {
			style = options.getInt(optionName, -1);
			setMetrics(baseFont);
		}
		model.update();
	}

	/**
	 * Notifications that the field options changed.
	 * @param options the Field Options object that changed.
	 * @param optionName the name of the property that changed.
	 * @param oldValue the old value of the property.
	 * @param newValue the new value of the property.
	 */
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		// for subclasses
	}

	/**
	 * Returns the Field name.
	 * @return the name.
	 */
	public String getFieldName() {
		return name;
	}

	/**
	 * Returns the starting x position for the fields generated by this factory.
	 * @return the start x.
	 */
	public int getStartX() {
		return startX;
	}

	/**
	 * Sets the starting x position for the fields generated by this factory.
	 * @param x the x position.
	 */
	public void setStartX(int x) {
		startX = x;
	}

	/**
	 * Returns the width of the fields generated by this factory.
	 * @return the width.
	 */
	public int getWidth() {
		return width;
	}

	/**
	 * Sets the width of the fields generated by this factory.
	 * @param w the width.
	 */
	public void setWidth(int w) {
		width = w;
	}

	/**
	 * Returns the FieldModel that this factory belongs to.
	 * @return the model.
	 */
	public FieldFormatModel getFieldModel() {
		return model;
	}

	/**
	 * Returns true if this FieldFactory is currently enabled to generate Fields.
	 * @return true if enabled.
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Turns on or off the generating of Fields by this FieldFactory.
	 * @param state if true, this factory will generate fields.
	 */
	public void setEnabled(boolean state) {
		enabled = state;
		model.modelChanged();
	}

	/**
	 * Returns true if this given field represents the given location
	 * @param listingField the field
	 * @param location the location 
	 * @return true if this given field represents the given location
	 */
	public boolean supportsLocation(ListingField listingField, ProgramLocation location) {
		BigInteger dummyIndex = BigInteger.ZERO;
		int dummyFieldNumber = 0;
		FieldLocation f = getFieldLocation(listingField, dummyIndex, dummyFieldNumber, location);
		return f != null;
	}

	/**
	 * Generates a Field based on the given information.
	 * @param obj The object that the generated field will report some information about.
	 * @param varWidth the additional distance along the x axis to place the generated field.
	 * @return the newly generated FactoryField that shows some property or information about
	 * the given object.
	 */
	public abstract ListingField getField(ProxyObj<?> obj, int varWidth);

	/**
	 * Return a FieldLocation that corresponds to the given index, fieldNum, and ProgramLocation
	 * IF and ONLY IF the given programLocation is the type generated by this class's
	 * {@link #getFieldLocation(ListingField, BigInteger, int, ProgramLocation)}.  Each
	 * FieldFactory should generate and process a unique ProgramLocation class.
	 *
	 * @param bf the ListingField at the current cursor.
	 * @param index the line index (corresponds to an address)
	 * @param fieldNum the index of field within the layout to try and get a FieldLocation.
	 * @param loc the ProgramLocation to be converted into a FieldLocation.
	 * @return the location.
	 */
	public abstract FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc);

	/**
	 * Returns the Program location for the given object, row, col, and groupPath
	 * @param row the row within this field
	 * @param col the col on the given row within this field.
	 * @param bf the ListingField containing the cursor.
	 * @return the location.
	 */
	public abstract ProgramLocation getProgramLocation(int row, int col, ListingField bf);

	/**
	 * Used to specify which format models this field can belong to.
	 * @param category the category for this field
	 * @param proxyObjectClass the type of proxy object used by this field
	 * @return true if this class accepts the given category.
	 */
	public abstract boolean acceptsType(int category, Class<?> proxyObjectClass);

	protected boolean hasSamePath(ListingField bf, ProgramLocation loc) {
		Object obj = bf.getProxy().getObject();
		if (obj instanceof Data) {
			Data data = (Data) obj;
			int[] path1 = data.getComponentPath();
			int[] path2 = loc.getComponentPath();
			if (path1 == null) {
				return path2 == null || path2.length == 0;
			}
			if (path2 == null) {
				return path1.length == 0;
			}
			if (path1.length != path2.length) {
				return false;
			}
			for (int i = 0; i < path2.length; i++) {
				if (path1[i] != path2[i]) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Returns a description of the fields generated by this factory.
	 * @return the text.
	 */
	public String getFieldText() {
		return name;
	}

	/**
	 * Returns the font metrics used by this field factory
	 * @return the metrics.
	 */
	public FontMetrics getMetrics() {
		return getMetrics(style);
	}

	protected FontMetrics getMetrics(int fontStyle) {
		if (fontStyle == -1) {
			return defaultMetrics;
		}
		return fontMetrics[fontStyle];
	}

	@SuppressWarnings("deprecation") // we know
	private void setMetrics(Font newFont) {
		defaultMetrics = Toolkit.getDefaultToolkit().getFontMetrics(newFont);
		for (int i = 0; i < fontMetrics.length; i++) {
			Font font = newFont.deriveFont(i); // i is looping over the 4 font styles PLAIN, BOLD, ITALIC, and BOLDITALIC
			fontMetrics[i] = Toolkit.getDefaultToolkit().getFontMetrics(font);
		}
	}

	protected String simplifyTemplates(String input) {
		return templateSimplifier.simplify(input);
	}
}
