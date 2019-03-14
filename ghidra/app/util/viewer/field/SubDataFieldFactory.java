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
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.SubDataFieldLocation;
import ghidra.util.classfinder.ClassSearcher;

/**
  *  Generates data value Fields for data subcomponents.
  *  <P> 
  *  This field is not meant to be loaded by the {@link ClassSearcher}, hence the X in the name.
  */
public class SubDataFieldFactory extends OperandFieldFactory {

	private int[] componentPath;

	/**
	 * Constructor
	 * @param name the name of the field
	 * @param path the component path for the data
	 */
	public SubDataFieldFactory(String name, int[] path) {
		super();
		this.componentPath = path;
		this.name = name;
	}

	/**
	  * Constructor
	  * @param provider The FieldProvider object that serves as the SubDataFieldFactory factory.
	  * @param model The Field model that will use this Address factory.
	  */
	private SubDataFieldFactory(String name, int[] componentPath, FieldFormatModel model,
			HighlightProvider hlProvider, ToolOptions displayOptions, ToolOptions fieldOptions) {
		super(model, hlProvider, displayOptions, fieldOptions);
		this.name = name;
		this.componentPath = componentPath;
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
		if (obj instanceof Data) {
			Data data = (Data) obj;
			Data subData = getComponent(data, componentPath);
			if (subData != null) {
				return super.getField(subData, proxy, varWidth);
			}
		}
		return null;
	}

	private Data getComponent(Data data, int[] path) {
		for (int element : path) {
			Data d = data.getComponent(element);
			if (d == null) {
				return data;
			}
			data = d;
		}
		return data;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (obj instanceof Data) {
			Data data = (Data) obj;

			Data subData = getComponent(data, componentPath);
			Address refAddr = null;
			if (subData != null) {
				Object value = subData.getValue();
				if (value instanceof Address) {
					refAddr = (Address) value;
				}
			}
			return new SubDataFieldLocation(data.getProgram(), data.getMinAddress(), null,
				data.getComponentPath(), refAddr,
				codeUnitFormat.getDataValueRepresentationString(data), col, getFieldName());
		}
		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (!(loc instanceof SubDataFieldLocation)) {
			return null;
		}

		SubDataFieldLocation subLoc = (SubDataFieldLocation) loc;

		if (!subLoc.getFieldName().equals(getFieldName())) {
			return null;
		}

		if (!hasSamePath(bf, loc)) {
			return null;
		}

		return getFieldLocation(index, fieldNum, bf, 0, subLoc.getCharOffset());
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return false;
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new SubDataFieldFactory(name, componentPath, formatModel, provider, displayOptions,
			fieldOptions);
	}

}
