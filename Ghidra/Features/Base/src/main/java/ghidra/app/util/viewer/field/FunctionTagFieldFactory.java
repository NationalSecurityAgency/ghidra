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

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.field.ListingColors.FunctionColors;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.FunctionProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.util.FunctionTagFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
  *  Generates a text label that lists the function tags for each {@link Function}. The
  *  label will will appear as part of the FUNCTION group in the field map.
  */
public class FunctionTagFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "Function Tags";

	/**
	 * Default Constructor
	 */
	public FunctionTagFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * 
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private FunctionTagFieldFactory(FieldFormatModel model, ListingHighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {

		if (!enabled) {
			return null;
		}

		// Exit if this isn't at a function.
		Object obj = proxy.getObject();
		if (!(obj instanceof FunctionDB)) {
			return null;
		}
		FunctionDB function = (FunctionDB) obj;

		// Create the text block we want to show.
		List<FieldElement> textElements = createFunctionTagElements(function);
		if (textElements == null) {
			return null;
		}

		return ListingTextField.createSingleLineTextField(this, proxy,
			new CompositeFieldElement(textElements), startX + varWidth, width, hlProvider);
	}

	/**
	 * Overridden to ensure that we return` a {@link FunctionTagFieldLocation} instance. 
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		if (proxy instanceof FunctionProxy) {
			FunctionProxy functionProxy = (FunctionProxy) proxy;
			Function function = functionProxy.getObject();
			return new FunctionTagFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				function.getCallFixup(), col);
		}
		return null;
	}

	/**
	 * Overridden to ensure that we only place function tag text on the header of a 
	 * function. 
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField listingField, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {

		if (programLoc instanceof FunctionTagFieldLocation) {
			FunctionTagFieldLocation fieldLocation = (FunctionTagFieldLocation) programLoc;
			return new FieldLocation(index, fieldNum, 0, fieldLocation.getCharOffset());
		}
		return null;
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return (category == FieldFormatModel.FUNCTION);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, ListingHighlightProvider provider,
			ToolOptions toolOptions, ToolOptions fieldOptions) {
		return new FunctionTagFieldFactory(formatModel, provider, toolOptions, fieldOptions);
	}

	/**
	 * Creates a tags list field to be show at the beginning of each function that shows the tags
	 * assigned to that function. 
	 * 
	 * @param function the function to retrieve the tags from
	 * @return the elements
	 */
	protected List<FieldElement> createFunctionTagElements(FunctionDB function) {

		Collection<String> tagNames = getTags(function);
		if (tagNames == null || tagNames.isEmpty()) {
			return null;
		}

		ArrayList<FieldElement> textElements = new ArrayList<>();
		AttributedString as;
		int elementIndex = 0;

		as = new AttributedString("Tags: ", ListingColors.SEPARATOR, getMetrics());
		textElements.add(new TextFieldElement(as, elementIndex++, 0));

		String tagNamesStr = StringUtils.join(tagNames, ", ");
		as = new AttributedString(tagNamesStr, FunctionColors.TAG, getMetrics());
		textElements.add(new TextFieldElement(as, elementIndex++, 0));

		return textElements;
	}

	/**
	 * Returns all function tags associated with the given function.
	 * 
	 * @param function the function to retrieve the tags from
	 * @return list of function tag names
	 */
	private Collection<String> getTags(FunctionDB function) {

		if (function == null) {
			return Collections.emptyList();
		}

		Collection<FunctionTag> tags = function.getTags();
		if (tags.isEmpty()) {
			return Collections.emptyList();
		}

		// @formatter:off
		return tags.stream()
				   .sorted()
				   .map(t -> t.getName())
				   .collect(Collectors.toList());
		// @formatter:on
	}
}
