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
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
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
	public static final Font DEFAULT_FIELD_FONT = new Font("monospaced", Font.PLAIN, 12);

	protected FieldFormatModel model;
	protected String name;
	protected int startX;
	protected int width;
	protected Color color;
	protected Color underlineColor = Color.BLUE;
	private FontMetrics defaultMetrics;
	private FontMetrics[] fontMetrics = new FontMetrics[4];
	protected Font baseFont;
	protected int style = -1;
	protected boolean enabled = true;
	protected HighlightProvider hlProvider;

	protected String colorOptionName;
	protected String styleOptionName;
	protected Options displayOptions;

	/**
	 * Base constructor
	 * @param name the name of the field
	 * @param model the model that the field belongs to.
	 * @param highlightProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	protected FieldFactory(String name, FieldFormatModel model, HighlightProvider highlightProvider,
			Options displayOptions, Options fieldOptions) {
		this.name = name;
		this.model = model;
		this.hlProvider = highlightProvider;
		colorOptionName = name + " Color";
		styleOptionName = name + " Style";

		width = 100;

		this.displayOptions = displayOptions;
		initDisplayOptions();

		fieldOptions.getOptions(name).setOptionsHelpLocation(
			new HelpLocation("CodeBrowserPlugin", name));
	}

	protected void initDisplayOptions() {
		baseFont = SystemUtilities.adjustForFontSizeOverride(
			displayOptions.getFont(FONT_OPTION_NAME, DEFAULT_FIELD_FONT));
		// For most fields (defined in optionsGui) these will be set. But "ad hoc" fields won't,
		// so register something.  A second registration won't change the original

		displayOptions.registerOption(colorOptionName, Color.BLACK, null,
			"Sets the " + colorOptionName);
		displayOptions.registerOption(styleOptionName, -1, null, "Sets the " + style);

		color = displayOptions.getColor(colorOptionName, getDefaultColor());
		style = displayOptions.getInt(styleOptionName, -1);
		underlineColor = displayOptions.getColor(OptionsGui.UNDERLINE.getColorOptionName(),
			OptionsGui.UNDERLINE.getDefaultColor());
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
	 * Notification that the Options have changed.
	 * @param options the Options object that changed. Will be either the display
	 * options or the field options.
	 * @param optionName the name of the property that changed.
	 * @param oldValue the old value of the property.
	 * @param newValue the new value of the property.
	 */
	public void optionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		if (options == displayOptions) {
			displayOptionsChanged(options, optionName, oldValue, newValue);
		}
		else {
			fieldOptionsChanged(options, optionName, oldValue, newValue);
		}
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
	 */
	public abstract FieldFactory newInstance(FieldFormatModel formatModel,
			HighlightProvider highlightProvider, ToolOptions options, ToolOptions fieldOptions);

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
		else if (optionName.equals(colorOptionName)) {
			color = (Color) newValue;
		}
		else if (optionName.equals(styleOptionName)) {
			style = options.getInt(optionName, -1);
			setMetrics(baseFont);
		}
		else if (optionName.equals(OptionsGui.UNDERLINE.getColorOptionName())) {
			underlineColor = (Color) newValue;
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
	 */
	public String getFieldName() {
		return name;
	}

	/**
	 * Returns the default field color.
	 */
	public Color getDefaultColor() {
		return Color.BLACK;
	}

	/**
	 * Returns the starting x position for the fields generated by this
	 * factory.
	 */
	public int getStartX() {
		return startX;
	}

	/**
	 * Sets the starting x position for the fields generated by this factory.
	 */
	public void setStartX(int x) {
		startX = x;
	}

	/**
	 * Returns the width of the fields generated by this factory.
	 */
	public int getWidth() {
		return width;
	}

	/**
	 * Sets the width of the fields generated by this factory.
	 */
	public void setWidth(int w) {
		width = w;
	}

	/**
	 * Returns the FieldModel that this factory belongs to.
	 */
	public FieldFormatModel getFieldModel() {
		return model;
	}

	/**
	 * Returns true if this FieldFactory is currently enabled to generate Fields.
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
	 * {@link #getFieldLocation(ListingField, BigInteger, int, ProgramLocation)}.  Each FieldFactory
	 * should generate and process a unique ProgramLocation class.
	 * @param bf the ListingField at the current cursor.
	 * @param index the line index (corresponds to an address)
	 * @param fieldNum the index of field within the layout to try and get a FieldLocation.
	 * @param loc the ProgramLocation to be converted into a FieldLocation.
	 */
	public abstract FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc);

	/**
	 * Returns the Program location for the given object, row, col, and groupPath
	 * @param row the row within this field
	 * @param col the col on the given row within this field.
	 * @param bf the ListingField containing the cursor.
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
	 */
	public String getFieldText() {
		return name;
	}

	/**
	 * Returns the font metrics used by this field factory
	 */
	public FontMetrics getMetrics() {
		return getMetrics(style);
	}

	/**
	 * @return Returns the metrics.
	 */
	protected FontMetrics getMetrics(int fontStyle) {
		if (fontStyle == -1) {
			return defaultMetrics;
		}
		return fontMetrics[fontStyle];
	}

	@SuppressWarnings("deprecation")
	// we know
	private void setMetrics(Font newFont) {
		defaultMetrics = Toolkit.getDefaultToolkit().getFontMetrics(newFont);
		for (int i = 0; i < fontMetrics.length; i++) {
			Font font = new Font(newFont.getFamily(), i, newFont.getSize());
			fontMetrics[i] = Toolkit.getDefaultToolkit().getFontMetrics(font);
		}
	}
}
