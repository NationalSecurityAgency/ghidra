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
package ghidra.app.util.viewer.format;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.jdom.Element;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.classfinder.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;

/**
 * Class to manage the set of format models.
 */
public class FormatManager implements OptionsChangeListener {
	public static final String ARRAY_OPTIONS_GROUP = "Array Options";
	private static final String HIGHLIGHT_GROUP = "Cursor Text Highlight";
	public static final String HIGHLIGHT_COLOR_NAME =
		HIGHLIGHT_GROUP + Options.DELIMITER + "Highlight Color";
	public static final String HIGHLIGHT_ALT_COLOR_NAME =
		HIGHLIGHT_GROUP + Options.DELIMITER + "Alternate Highlight Color";
	public final static String ARRAY_DISPLAY_OPTIONS =
		ARRAY_OPTIONS_GROUP + Options.DELIMITER + "Array Display Options";
	public final static String ARRAY_DISPLAY_DESCRIPTION = "Adjusts the Array Field display";

	private static final int NUM_MODELS = 7;

	private static final String[] NAMES = { "Address Break", "Plate", "Function", "Variable",
		"Instruction/Data", "Open Data", "Array" };
	private static final Class<?>[] PROXY_CLASSES = { Address.class, CodeUnit.class, Function.class,
		Variable.class, CodeUnit.class, CodeUnit.class, CodeUnit.class };
	private FieldFormatModel[] models = new FieldFormatModel[NUM_MODELS];
	private WeakSet<FormatModelListener> formatListeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();
	private int maxNumRows = 0;

	private FieldFactory[] factorys;
	private ToolOptions fieldOptions;
	private ToolOptions displayOptions;
	private boolean initialized = false;
	private MultipleHighlighterProvider highlightProvider;
	private ServiceProvider serviceProvider;
	private int arrayValuesPerLine = 1;
	private boolean groupArrayElements = true;

	// NOTE:  Unused custom format code was removed.  The custom format code last existed in
	// commit #204e7892bf2f110ebb05ca4beee3fe5b397f88c9.  

	/**
	 * Constructs a new FormatManager.
	 * 
	 * @param displayOptions the Options containing display options (color, fonts, etc)
	 * @param fieldOptions the Options contains specific field options.
	 */
	public FormatManager(ToolOptions displayOptions, ToolOptions fieldOptions) {
		this.fieldOptions = fieldOptions;
		this.displayOptions = displayOptions;
		highlightProvider = new MultipleHighlighterProvider();
		getFactorys();
		for (int i = 0; i < NUM_MODELS; i++) {
			models[i] = new FieldFormatModel(this, NAMES[i], i, PROXY_CLASSES[i], factorys);
			models[i].restoreFromXml(getDefaultModel(i));
		}
		initialized = true;
		setRowIDs();
		displayOptions.addOptionsChangeListener(this);
		fieldOptions.addOptionsChangeListener(this);
		getArrayDisplayOptions(fieldOptions);

	}

	private void getArrayDisplayOptions(Options options) {
		options.registerOption(ARRAY_DISPLAY_OPTIONS, OptionType.CUSTOM_TYPE,
			new ArrayElementWrappedOption(), null, ARRAY_DISPLAY_DESCRIPTION,
			new ArrayElementPropertyEditor());
		CustomOption option = options.getCustomOption(ARRAY_DISPLAY_OPTIONS, null);
		if (option instanceof ArrayElementWrappedOption) {
			ArrayElementWrappedOption arrayOption = (ArrayElementWrappedOption) option;
			arrayValuesPerLine = arrayOption.getArrayElementsPerLine();
			groupArrayElements = arrayOption.showMultipleArrayElementPerLine();
		}
	}

	public FormatManager createClone() {
		ToolOptions newDisplayOptions = displayOptions.copy();
		ToolOptions newFieldOptions = fieldOptions.copy();
		FormatManager newManager = new FormatManager(newDisplayOptions, newFieldOptions);
		SaveState saveState = new SaveState();
		saveState(saveState);
		newManager.readState(saveState);
		return newManager;
	}

	public void dispose() {
		fieldOptions.removeOptionsChangeListener(this);
		displayOptions.removeOptionsChangeListener(this);
	}

	/**
	 * Sets the service provider used by the field factory objects.
	 * 
	 * @param provider the service provider
	 */
	public void setServiceProvider(ServiceProvider provider) {
		this.serviceProvider = provider;
		notifyServicesChanged();
	}

	private void notifyServicesChanged() {
		for (int i = 0; i < NUM_MODELS; i++) {
			models[i].servicesChanged();
		}
	}

	private void getFactorys() {
		ClassFilter filter = new ClassExclusionFilter(DummyFieldFactory.class,
			SpacerFieldFactory.class, SubDataFieldFactory.class);
		List<FieldFactory> instances = ClassSearcher.getInstances(FieldFactory.class, filter);
		List<FieldFactory> list = new ArrayList<>();
		for (FieldFactory fieldFactory : instances) {
			if (fieldFactory instanceof SpacerFieldFactory) {
				continue;
			}
			list.add(fieldFactory);
		}
		factorys = new FieldFactory[list.size()];
		list.toArray(factorys);
	}

	/**
	 * Adds a listener to be notified when a format changes.
	 * 
	 * @param listener the listener to be added.
	 */
	public void addFormatModelListener(FormatModelListener listener) {
		formatListeners.add(listener);
	}

	/**
	 * Removes the given listener from the list of listeners to be notified of a
	 * format change.
	 * 
	 * @param listener the listener to be removed.
	 */
	public void removeFormatModleListener(FormatModelListener listener) {
		formatListeners.remove(listener);
	}

	/**
	 * Returns the total number of model in the format manager.
	 */
	public int getNumModels() {
		return NUM_MODELS;
	}

	/**
	 * Returns the format model for the given index.
	 * 
	 * @param index the index of the format model to return.
	 */
	public FieldFormatModel getModel(int index) {
		return models[index];
	}

	/**
	 * Returns the format model for the address break (divider)
	 */
	public FieldFormatModel getDividerModel() {
		return models[FieldFormatModel.DIVIDER];
	}

	/**
	 * Returns the format model for the plate field
	 */
	public FieldFormatModel getPlateFormat() {
		return models[FieldFormatModel.PLATE];
	}

	/**
	 * Returns the format model for the function signature
	 */
	public FieldFormatModel getFunctionFormat() {
		return models[FieldFormatModel.FUNCTION];
	}

	/**
	 * Returns the format model for the function variables.
	 */
	public FieldFormatModel getFunctionVarFormat() {
		return models[FieldFormatModel.FUNCTION_VARS];
	}

	/**
	 * Returns the format model for a code unit.
	 */
	public FieldFormatModel getCodeUnitFormat() {
		return models[FieldFormatModel.INSTRUCTION_OR_DATA];
	}

	/**
	 * Returns the format model to use for the internals of open structures.
	 * 
	 * @param data
	 *            the data code unit to get the format model for.
	 */
	public FieldFormatModel getOpenDataFormat(Data data) {

		if (groupArrayElements && isPrimitiveArrayElement(data)) {
			if (data.getComponentIndex() % arrayValuesPerLine == 0) {
				return models[FieldFormatModel.ARRAY];
			}
			return null;
		}

		return models[FieldFormatModel.OPEN_DATA];
	}

	private boolean isPrimitiveArrayElement(Data data) {
		Data parent = data.getParent();
		if (parent == null) {
			return false;
		}
		if (!(parent.getDataType() instanceof Array)) {
			return false;
		}
		DataType type = data.getBaseDataType();
		return type.getLength() > 0 && type instanceof AbstractIntegerDataType ||
			type instanceof DefaultDataType;
	}

	/**
	 * update all listeners that a model has changed.
	 */
	public void update() {
		modelChanged(null);

	}

	/**
	 * Returns the Options used for display properties.
	 */
	public ToolOptions getDisplayOptions() {
		return displayOptions;
	}

	/**
	 * Returns the Options used for field specific properties.
	 */
	public ToolOptions getFieldOptions() {
		return fieldOptions;
	}

	/**
	 * Notifies listeners that the given model has changed.
	 * 
	 * @param model the format model that changed.
	 */
	public void modelChanged(FieldFormatModel model) {
		if (!initialized) {
			return;
		}
		for (FormatModelListener l : formatListeners) {
			l.formatModelChanged(model);
		}
		setRowIDs();
	}

	/**
	 * Returns the width of the widest model in this manager.
	 */
	public int getMaxWidth() {
		int maxWidth = 0;
		for (FieldFormatModel element : models) {
			maxWidth = Math.max(maxWidth, element.getWidth());
		}
		return maxWidth;
	}

	public int getMaxRowCount() {
		int maxRowCount = 0;
		for (FieldFormatModel element : models) {
			maxRowCount = Math.max(maxRowCount, element.getNumRows());
		}
		return maxRowCount;
	}

	private Element getDefaultModel(int modelID) {
		switch (modelID) {
			case FieldFormatModel.DIVIDER:
				return getDefaultDividerFormat();
			case FieldFormatModel.PLATE:
				return getDefaultPlateFormat();
			case FieldFormatModel.FUNCTION:
				return getDefaultFunctionFormat();
			case FieldFormatModel.FUNCTION_VARS:
				return getDefaultVariableFormat();
			case FieldFormatModel.INSTRUCTION_OR_DATA:
				return getDefaultCodeFormat();
			case FieldFormatModel.OPEN_DATA:
				return getDefaultSubDataFormat();
			case FieldFormatModel.ARRAY:
				return getDefaultArrayFormat();
		}
		return null;
	}

	private Element getDefaultDividerFormat() {
		Element root = new Element("FORMAT");

		Element rowElem = new Element("ROW");

		Element colElem = new Element("FIELD");

		colElem.setAttribute("NAME", "Separator");
		colElem.setAttribute("WIDTH", "80");
		colElem.setAttribute("ENABLED", "true");

		rowElem.addContent(colElem);
		root.addContent(rowElem);
		return root;

	}

	private Element getDefaultPlateFormat() {
		Element root = new Element("FORMAT");

		Element rowElem = new Element("ROW");// 1st row

		Element colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "200");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Memory Block Start");
		colElem.setAttribute("WIDTH", "440");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);
		root.addContent(rowElem);

		rowElem = new Element("ROW");// 2nd row

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "200");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Plate Comment");
		colElem.setAttribute("WIDTH", "440");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);
		return root;
	}

	private Element getDefaultFunctionFormat() {
		Element root = new Element("FORMAT");
		Element rowElem = new Element("ROW");

		Element colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "200");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Function Signature");
		colElem.setAttribute("WIDTH", "410");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Function Repeatable Comment");
		colElem.setAttribute("WIDTH", "300");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);
		root.addContent(rowElem);

		rowElem = new Element("ROW");

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "220");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Thunked-Function");
		colElem.setAttribute("WIDTH", "300");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);
		root.addContent(rowElem);

		rowElem = new Element("ROW");

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "220");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Function Call-Fixup");
		colElem.setAttribute("WIDTH", "300");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);
		root.addContent(rowElem);

		rowElem = new Element("ROW");

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "220");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Function Tags");
		colElem.setAttribute("WIDTH", "300");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);
		root.addContent(rowElem);

		rowElem = new Element("ROW");

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "220");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Register");
		colElem.setAttribute("WIDTH", "300");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);
		root.addContent(rowElem);

		return root;

	}

	private Element getDefaultVariableFormat() {
		Element root = new Element("FORMAT");
		Element rowElem = new Element("ROW");

		Element colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "90");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Variable Type");
		colElem.setAttribute("WIDTH", "110");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Variable Location");
		colElem.setAttribute("WIDTH", "120");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Variable Name");
		colElem.setAttribute("WIDTH", "280");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Variable XRef Header");
		colElem.setAttribute("WIDTH", "90");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Variable XRef");
		colElem.setAttribute("WIDTH", "130");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Variable Comment");
		colElem.setAttribute("WIDTH", "110");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);
		return root;

	}

	private Element getDefaultCodeFormat() {
		Element root = new Element("FORMAT");

		Element rowElem = new Element("ROW");

		Element colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "90");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Register Transition");
		colElem.setAttribute("WIDTH", "300");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);

		rowElem = new Element("ROW");

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "200");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Pre-Comment");
		colElem.setAttribute("WIDTH", "440");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);

		rowElem = new Element("ROW");

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "188");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Label");
		colElem.setAttribute("WIDTH", "350");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "XRef Header");
		colElem.setAttribute("WIDTH", "90");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "XRef");
		colElem.setAttribute("WIDTH", "240");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);
		rowElem = new Element("ROW");

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "+");
		colElem.setAttribute("WIDTH", "20");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Address");
		colElem.setAttribute("WIDTH", "100");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Bytes");
		colElem.setAttribute("WIDTH", "80");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "10");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Parallel ||");
		colElem.setAttribute("WIDTH", "20");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Mnemonic");
		colElem.setAttribute("WIDTH", "70");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "10");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Operands");
		colElem.setAttribute("WIDTH", "340");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "EOL Comment");
		colElem.setAttribute("WIDTH", "240");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);
		rowElem = new Element("ROW");

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "380");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "PCode");
		colElem.setAttribute("WIDTH", "400");
		colElem.setAttribute("ENABLED", "false");
		rowElem.addContent(colElem);

		root.addContent(rowElem);
		rowElem = new Element("ROW");

		colElem = new Element("FIELD");
		colElem.setAttribute("WIDTH", "200");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Post-Comment");
		colElem.setAttribute("WIDTH", "440");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);
		rowElem = new Element("ROW");

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Space");
		colElem.setAttribute("WIDTH", "640");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);
		return root;

	}

	private Element getDefaultSubDataFormat() {
		Element root = new Element("FORMAT");

		Element rowElem = new Element("ROW");
		Element colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "+");
		colElem.setAttribute("WIDTH", "20");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Address");
		colElem.setAttribute("WIDTH", "100");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Bytes");
		colElem.setAttribute("WIDTH", "110");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Mnemonic");
		colElem.setAttribute("WIDTH", "70");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Operands");
		colElem.setAttribute("WIDTH", "170");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Field Name");
		colElem.setAttribute("WIDTH", "100");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "EOL Comment");
		colElem.setAttribute("WIDTH", "140");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "XRef Header");
		colElem.setAttribute("WIDTH", "90");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "XRef");
		colElem.setAttribute("WIDTH", "240");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);
		return root;

	}

	private Element getDefaultArrayFormat() {
		Element root = new Element("FORMAT");

		Element rowElem = new Element("ROW");
		Element colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "+");
		colElem.setAttribute("WIDTH", "20");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Address");
		colElem.setAttribute("WIDTH", "100");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Field Name");
		colElem.setAttribute("WIDTH", "100");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		colElem = new Element("FIELD");
		colElem.setAttribute("NAME", "Array Values");
		colElem.setAttribute("WIDTH", "600");
		colElem.setAttribute("ENABLED", "true");
		rowElem.addContent(colElem);

		root.addContent(rowElem);
		return root;

	}

	private void setRowIDs() {
		int baseRowID = 0;
		for (FieldFormatModel element : models) {
			element.setBaseRowID(baseRowID);
			baseRowID += element.getNumRows();
		}
		maxNumRows = baseRowID;
	}

	/**
	 * Returns the maximum number of possible rows in a layout. This would only
	 * occur if some address had every possible type of information to be displayed.
	 */
	public int getMaxNumRows() {
		return maxNumRows;
	}

	/**
	 * Resets the model with the given id to its default format.
	 * 
	 * @param modelID the id of the model to reset.
	 */
	public void setDefaultFormat(int modelID) {
		if (modelID < NUM_MODELS) {
			models[modelID].restoreFromXml(getDefaultModel(modelID));
		}
	}

	/**
	 * Resets all format models to their default format.
	 */
	public void setDefaultFormats() {
		for (int i = 0; i < NUM_MODELS; i++) {
			models[i].restoreFromXml(getDefaultModel(i));
		}

	}

	/**
	 * Adds a HighlightProvider
	 * 
	 * @param provider
	 *            the provider to use.
	 * @see #removeHighlightProvider(HighlightProvider)
	 * @see #getHighlightProviders()
	 */
	public void addHighlightProvider(HighlightProvider provider) {
		if (provider instanceof MultipleHighlighterProvider) {
			throw new AssertException("Cannot set FormatManager's internal highlight provider " +
				"on another FormatManager!");
		}
		highlightProvider.addHighlightProvider(provider);
	}

	/**
	 * Removes the provider
	 * 
	 * @param provider
	 *            the provider to remove.
	 * @see #addHighlightProvider(HighlightProvider)
	 */
	public void removeHighlightProvider(HighlightProvider provider) {
		highlightProvider.removeHighlightProvider(provider);
	}

	/**
	 * Gets all {@link HighlightProvider}s installed on this FormatManager via the 
	 * {@link #addHighlightProvider(HighlightProvider)}.
	 * 
	 * @return all {@link HighlightProvider}s installed on this FormatManager.
	 */
	public List<HighlightProvider> getHighlightProviders() {
		return highlightProvider.getHighlightProviders();
	}

	/**
	 * Returns the {@link HighlightProvider} that should be used when creating {@link FieldFactory}
	 * objects.
	 */
	public HighlightProvider getFormatHighlightProvider() {
		return highlightProvider;
	}

	@Override
	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		for (int i = 0; i < NUM_MODELS; i++) {
			models[i].optionsChanged(options, name, oldValue, newValue);
		}
		getArrayDisplayOptions(options);

		modelChanged(null);
	}

	/**
	 * Saves the state of this LayoutManager to the SaveState object.
	 * 
	 * @param saveState the SaveState object to write to.
	 */
	public void saveState(SaveState saveState) {
		for (int i = 0; i < NUM_MODELS; i++) {
			saveState.putXmlElement(models[i].getName(), models[i].saveToXml());
		}
	}

	/**
	 * Restores the state of this LayoutController from the given SaveState
	 * object.
	 * 
	 * @param saveState the SaveState to read from.
	 */
	public void readState(SaveState saveState) {
		initialized = false;
		for (int i = 0; i < NUM_MODELS; i++) {
			if (saveState.hasValue(models[i].getName())) {
				models[i].restoreFromXml(saveState.getXmlElement(models[i].getName()));
			}
			else {
				models[i].restoreFromXml(getDefaultModel(i));
			}
		}
		initialized = true;
		modelChanged(null);
	}

	public ServiceProvider getServiceProvider() {
		return serviceProvider;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MultipleHighlighterProvider implements HighlightProvider {

		private List<HighlightProvider> highlightProviders = new CopyOnWriteArrayList<>();

		@Override
		public Highlight[] getHighlights(String text, Object obj,
				Class<? extends FieldFactory> fieldFactoryClass, int cursorTextOffset) {

			//
			// Gather and use all other registered providers.  
			// 
			// Note: we loop backwards here as a hacky method to make sure that the middle-mouse
			//       highlighter runs last and is thus painted above other highlights.  This 
			//       works because the middle-mouse highlighter is installed before any other 
			//       highlighters.
			List<Highlight> list = new ArrayList<>();
			int size = highlightProviders.size();
			for (int i = size - 1; i >= 0; i--) {
				HighlightProvider provider = highlightProviders.get(i);
				Highlight[] highlights =
					provider.getHighlights(text, obj, fieldFactoryClass, cursorTextOffset);
				for (Highlight highlight : highlights) {
					list.add(highlight);
				}
			}

			return list.toArray(new Highlight[list.size()]);
		}

		List<HighlightProvider> getHighlightProviders() {
			return new ArrayList<>(highlightProviders);
		}

		void addHighlightProvider(HighlightProvider provider) {
			if (!highlightProviders.contains(provider)) {
				highlightProviders.add(provider);
			}
		}

		void removeHighlightProvider(HighlightProvider provider) {
			highlightProviders.remove(provider);
		}
	}

}
