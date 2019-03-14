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

import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.util.IndentFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
  *  Generates Open/Close Fields.
  */
public class OpenCloseFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "+";

	public OpenCloseFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private OpenCloseFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		servicesChanged();
	}

	/**
	 * Returns the FactoryField for the given object at index index.
	 * @param varWidth the amount of variable width spacing for any fields
	 * before this one.
	 * @param proxy the object whose properties should be displayed.
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();

		if (!enabled) {
			return null;
		}
		boolean canOpen = false;
		int indentLevel = 0;
		boolean isLast = false;
		if (obj instanceof Data) {
			Data data = (Data) obj;
			canOpen = (data.getNumComponents() > 0);
			indentLevel = computeIndentLevel(data);
			isLast = computeIsLast(data);
		}

		if (canOpen) {
			return new OpenCloseField(this, proxy, indentLevel, getMetrics(), startX + varWidth,
				width, isLast);
		}
		else if (indentLevel > 0) {
			return new IndentField(this, proxy, indentLevel, getMetrics(), startX + varWidth, width,
				isLast);
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#servicesChanged()
	 */
	@Override
	public void servicesChanged() {
	}

	/**
	 * Computes if the given data is the last component at its level.
	 */
	private boolean computeIsLast(Data data) {
		Data parent = data.getParent();
		if (parent != null) {
			Data d2 = parent.getComponent(parent.getNumComponents() - 1);
			if (d2 == data) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Computes the sub-component level of the given data object.
	 */
	private int computeIndentLevel(Data data) {
		int indentLevel = 0;
		while ((data = data.getParent()) != null) {
			indentLevel++;
		}
		return indentLevel;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof Data)) {
			return null;
		}
		Data data = (Data) obj;
		return new IndentFieldLocation(data.getProgram(), data.getMinAddress(),
			data.getComponentPath());
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {

		if (!(programLoc instanceof IndentFieldLocation)) {
			return null;
		}
		if (!hasSamePath(bf, programLoc)) {
			return null;
		}
		return new FieldLocation(index, fieldNum, 0, 0);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#acceptsType(int, java.lang.Class)
	 */
	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA ||
			category == FieldFormatModel.OPEN_DATA || category == FieldFormatModel.ARRAY);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel fieldModel, HighlightProvider provider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new OpenCloseFieldFactory(fieldModel, provider, displayOptions, fieldOptions);
	}

}
