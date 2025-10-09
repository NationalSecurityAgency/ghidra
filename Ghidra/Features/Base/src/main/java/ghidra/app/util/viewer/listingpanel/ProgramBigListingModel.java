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

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.util.viewer.field.DummyFieldFactory;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.proxy.*;
import ghidra.app.util.viewer.util.ProgramOpenCloseManager;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.datastruct.LRUMap;
import ghidra.util.task.TaskMonitor;

public class ProgramBigListingModel implements ListingModel, FormatModelListener,
		DomainObjectListener, ChangeListener, OptionsChangeListener {

	protected final Program program;
	private ProgramOpenCloseManager openCloseMgr;
	private FormatManager formatMgr;
	private ToolOptions fieldOptions;
	private boolean showExternalFunctionPointerFormat;
	private boolean showNonExternalFunctionPointerFormat;
	private final Listing listing;
	private DummyFieldFactory dummyFactory;
	private List<ListingModelListener> listeners = new ArrayList<>();

	// Use a cache so that simple arrowing to-and-fro with the keyboard will respond quickly
	private LayoutCache layoutCache = new LayoutCache();

	public ProgramBigListingModel(Program program, FormatManager formatMgr) {
		this.program = program;
		this.listing = program.getListing();
		this.formatMgr = formatMgr;
		openCloseMgr = new ProgramOpenCloseManager(program);
		dummyFactory = new DummyFieldFactory(formatMgr);
		formatMgr.addFormatModelListener(this);
		program.addListener(this);
		openCloseMgr.addChangeListener(this);
		fieldOptions = formatMgr.getFieldOptions();
		fieldOptions.addOptionsChangeListener(this);
		initOptions();
	}

	private void initOptions() {
		showExternalFunctionPointerFormat =
			fieldOptions.getBoolean(DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME, true);
		showNonExternalFunctionPointerFormat =
			fieldOptions.getBoolean(DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME, false);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME)) {
			showExternalFunctionPointerFormat = (Boolean) newValue;
			formatModelChanged(null);
		}
		else if (optionName.equals(DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME)) {
			showNonExternalFunctionPointerFormat = (Boolean) newValue;
			formatModelChanged(null);
		}

		// There are quite a few options that affect the display of the layouts.  Flush
		// the cache on any change, as it is simpler than tracking individual options.
		layoutCache.clear();
	}

	@Override
	public AddressSetView getAddressSet() {
		return program.getMemory();
	}

	@Override
	public void dispose() {
		program.removeListener(this);
		fieldOptions.removeOptionsChangeListener(this);
		formatMgr.removeFormatModleListener(this);
		listeners.clear();
	}

	@Override
	public void setFormatManager(FormatManager formatManager) {
		this.formatMgr = formatManager;
		formatMgr.addFormatModelListener(this);
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		notifyDataChanged(true);
	}

	@Override
	public Layout getLayout(Address addr, boolean isGapAddress) {

		Layout layout = layoutCache.get(addr, isGapAddress);
		if (layout == null) {
			layout = doGetLayout(addr, isGapAddress);
			layoutCache.put(addr, layout, isGapAddress);
		}
		return layout;
	}

	private Layout doGetLayout(Address addr, boolean isGapAddress) {
		List<RowLayout> list = new ArrayList<>();
		FieldFormatModel format;
		CodeUnit cu = listing.getCodeUnitAt(addr);
		List<Data> dataList = null;
		Function function = null;
		Data data = null;
		int indexSize = 1;

		if (cu != null) {
			indexSize = cu.getLength();
			function = listing.getFunctionAt(addr);
		}
		else if (addr.isExternalAddress()) {
			function = listing.getFunctionAt(addr);
		}
		if (cu instanceof Data) {
			data = (Data) cu;
			if (function == null && data.isPointer()) {
				function = getPointerReferencedFunction(data);
			}
		}
		else if (cu == null) {
			data = listing.getDataContaining(addr);
		}

		if (data != null && data.getNumComponents() > 0) {

			dataList = new ArrayList<>();

			addOpenData(dataList, data, addr);
			addUnionPostOpenData(dataList, data, addr);
		}
		boolean isClosedFunctionAddress = isClosedFunctionAddress(function, addr);

		if (isGapAddress) {
			format = formatMgr.getDividerModel();
			format.addLayouts(list, 0, new AddressProxy(this, addr));
		}
		if (cu != null) {
			format = formatMgr.getPlateFormat();
			format.addLayouts(list, 0, new CodeUnitProxy(this, program, cu));
		}
		if (function != null) {
			format = formatMgr.getFunctionFormat();
			format.addLayouts(list, 0, new FunctionProxy(this, program, addr, function));
			if (!isClosedFunctionAddress) {
				format = formatMgr.getFunctionVarFormat();
				boolean variablesOpen =
					openCloseMgr.isFunctionVariablesOpen(function.getEntryPoint());
				if (variablesOpen) {
					addReturn(addr, list, format, function);
					addParameters(addr, list, format, function);
					addLocals(addr, list, format, function);
				}
				else {
					format.addLayouts(list, 0,
						new ClosedVariableProxy(this, program, addr, function));
				}
			}
		}
		if (cu != null) {
			if (isClosedFunctionAddress) {
				format = formatMgr.getDividerModel();
			}
			else {
				format = formatMgr.getCodeUnitFormat();
			}
			CodeUnitProxy proxy = new CodeUnitProxy(this, program, cu);
			format.addLayouts(list, 0, proxy);
		}

		if (dataList != null) {
			for (Data d : dataList) {
				format = formatMgr.getOpenDataFormat(d);
				if (format != null) {
					format.addLayouts(list, 0, new DataProxy(this, program, d));
				}
				indexSize = d.getLength();
			}
			dataList = null;
		}

		if (list.size() > 0) {
			return new MultiRowLayout(list.toArray(new RowLayout[list.size()]), indexSize);
		}
		else if (cu != null) {
			ListingField f = dummyFactory.getField(new CodeUnitProxy(this, program, cu), 0);
			if (f != null) {
				return new MultiRowLayout(new SingleRowLayout(f), indexSize);
			}
		}
		return null;

	}

	private boolean isClosedFunctionAddress(Function function, Address addr) {
		if (function == null) {
			function = listing.getFunctionContaining(addr);
		}
		if (function == null) {
			return false;
		}
		return !openCloseMgr.isFunctionOpen(function.getEntryPoint());
	}

	private void addReturn(Address addr, List<RowLayout> list, FieldFormatModel format,
			Function function) {
		format.addLayouts(list, 0,
			new VariableProxy(this, program, addr, function, function.getReturn(), true));
	}

	private void addLocals(Address addr, List<RowLayout> list, FieldFormatModel format,
			Function function) {
		Variable[] vars = function.getLocalVariables();
		for (Variable var : vars) {
			format.addLayouts(list, 0,
				new VariableProxy(this, program, addr, function, var, false));
		}
	}

	private void addParameters(Address addr, List<RowLayout> list, FieldFormatModel format,
			Function function) {
		Parameter[] params = function.getParameters();
		for (Parameter param : params) {
			format.addLayouts(list, 0,
				new VariableProxy(this, program, addr, function, param, false));
		}
	}

	private Function getPointerReferencedFunction(Data data) {

		Reference ref = data.getPrimaryReference(0);
		if (ref == null) {
			return null;
		}
		if (ref.isExternalReference() && !showExternalFunctionPointerFormat) {
			return null;
		}
		if (!ref.isExternalReference() && !showNonExternalFunctionPointerFormat) {
			return null;
		}
		return listing.getFunctionAt(ref.getToAddress());
	}

	@Override
	public int getMaxWidth() {
		return formatMgr.getMaxWidth();
	}

	@Override
	public Address getAddressBefore(Address addr) {
		CodeUnit cu = listing.getCodeUnitContaining(addr);
		if (cu instanceof Data && !addr.equals(cu.getMinAddress()) && isOpenData(cu)) {
			Address prevAddr = findOpenDataBefore(addr, (Data) cu);
			if (prevAddr != null) {
				return prevAddr;
			}
			return cu.getMinAddress();
		}

		cu = listing.getCodeUnitBefore(addr);
		if (cu == null) {
			return null;
		}
		if (isOpenData(cu)) {
			return cu.getMaxAddress();
		}
		if (!isInClosedFunction(cu)) {
			return cu.getAddress();
		}
		Address firstAddress = getFirstAddressInClosedFunctionRange(cu);
		cu = listing.getCodeUnitAt(firstAddress);
		if (!isInClosedFunction(cu)) {
			return cu.getMinAddress();
		}
		return getAddressBefore(firstAddress);
	}

	@Override
	public Address getAddressAfter(Address address) {
		CodeUnit cu = listing.getCodeUnitContaining(address);
		if (cu instanceof Data) {
			Data data = (Data) cu;
			if (data.getNumComponents() > 0) {
				if (openCloseMgr.isDataOpen(data.getMinAddress())) {
					Address openAddr = findOpenDataAfter(address, data);
					if (openAddr != null) {
						return openAddr;
					}
				}
			}
		}
		cu = listing.getCodeUnitAfter(address);
		if (cu == null) {
			return null;
		}
		if (!isInClosedFunction(cu)) {
			return cu.getAddress();
		}
		Address lastAddress = getLastAddressInClosedFunctionRange(cu);
		return getAddressAfter(lastAddress);
	}

	private Address getLastAddressInClosedFunctionRange(CodeUnit cu) {
		Address address = cu.getAddress();
		Function f = listing.getFunctionContaining(address);
		AddressSetView body = f.getBody();
		AddressRange range = body.getRangeContaining(address);
		return range.getMaxAddress();
	}

	private Address getFirstAddressInClosedFunctionRange(CodeUnit cu) {
		Address address = cu.getAddress();
		Function f = listing.getFunctionContaining(address);
		AddressSetView body = f.getBody();
		AddressRange range = body.getRangeContaining(address);
		return range.getMinAddress();
	}

	private boolean isInClosedFunction(CodeUnit cu) {
		Address a = cu.getAddress();
		Function f = listing.getFunctionContaining(a);
		if (f == null) {
			return false;
		}
		Address entryPoint = f.getEntryPoint();
		if (a.equals(entryPoint)) {
			return false;
		}
		AddressSetView body = f.getBody();
		AddressRange rangeContaining = body.getRangeContaining(a);
		if (rangeContaining.getMinAddress().equals(a)) {
			return false;
		}
		if (openCloseMgr.isFunctionOpen(entryPoint)) {
			return false;
		}
		return true;
	}

	private Address findOpenDataAfter(Address address, Data parent) {
		Data data;
		DataType dt = parent.getBaseDataType();
		if (dt instanceof Union) {
			int index = openCloseMgr.getOpenDataIndex(parent);
			if (index < 0) {
				return null;
			}
			data = parent.getComponent(index);
		}
		else if (dt instanceof Structure) {
			int offset = (int) address.subtract(parent.getMinAddress());
			data = parent.getComponentContaining(offset);

			// Need to handle filler in a special way.
			if (data == null) {
				// So look for next non-filler address.
				offset++;
				int length = dt.getLength();
				for (; offset < length; offset++) {
					// If not beyond structure's end, check for non-filler.
					data = parent.getComponentAt(offset);
					if (data != null) { // Found non filler address so return it.
						return data.getMinAddress();
					}
				}
			}
		}
		else {
			int offset = (int) address.subtract(parent.getMinAddress());
			data = parent.getComponentContaining(offset);
		}
		if (data == null) {
			return null;
		}
		if (data.getNumComponents() > 0) {
			if (openCloseMgr.isDataOpen(data)) {
				Address openAddr = findOpenDataAfter(address, data);
				if (openAddr != null) {
					return openAddr;
				}
			}
		}
		int index = data.getComponentIndex();
		if (dt instanceof Union) {
			// otherwise just return the max address of this data component.
			if (index < parent.getNumComponents()) {
				Address maxAddr = parent.getComponent(index).getMaxAddress();
				if (maxAddr.compareTo(address) > 0) {
					return maxAddr;
				}
			}
			Address maxAddr = parent.getMaxAddress();
			if (maxAddr.compareTo(address) > 0) {
				return maxAddr;
			}
		}
		else {
			while (index < parent.getNumComponents() - 1) {
				index++;
				Data component = parent.getComponent(index);
				if (address.compareTo(component.getMinAddress()) < 0) {
					return component.getAddress();
				}
			}
		}
		return null;
	}

	public boolean isOpenData(CodeUnit cu) {
		if (cu instanceof Data) {
			Data data = (Data) cu;
			if (data.getNumComponents() > 0) {
				if (openCloseMgr.isDataOpen(data.getMinAddress())) {
					return true;
				}
			}
		}
		return false;
	}

	private Address findOpenDataBefore(Address addr, Data parent) {
		if (parent.getAddress().equals(addr)) {
			return null;
		}
		Data data;
		if (parent.getBaseDataType() instanceof Union) {
			int index =
				openCloseMgr.getOpenDataIndex(parent);
			if (index < 0) {
				return null;
			}
			data = parent.getComponent(index);
		}
		else {
			int offset = (int) addr.subtract(parent.getMinAddress());
			List<Data> componentsContaining = parent.getComponentsContaining(offset - 1);
			data = componentsContaining.isEmpty() ? null
					: componentsContaining.get(componentsContaining.size() - 1);
		}
		if (data == null) {
			return addr.previous();
		}

		if (data.getNumComponents() > 0) {
			if (openCloseMgr.isDataOpen(data)) {
				Address openAddr = findOpenDataBefore(addr, data);
				if (openAddr != null) {
					return openAddr;
				}
			}
		}
		if (!data.getAddress().equals(addr)) {
			return data.getAddress();
		}

		int index = data.getComponentIndex();
		if (index > 0) {
			return parent.getComponent(index - 1).getAddress();
		}
		return null;
	}

	private void addOpenData(List<Data> list, Data data, Address addr) {
		Address dataAddr = data.getMinAddress();
		if (openCloseMgr.isDataOpen(data)) {
			DataType dt = data.getBaseDataType();
			if (dt instanceof Union) {
				int openIndex =
					openCloseMgr.getOpenDataIndex(data);
				int numComps = ((Union) dt).getNumComponents();
				if (openIndex < 0) {
					openIndex = numComps;
				}
				for (int i = 0; i <= openIndex && i < numComps; i++) {
					Data tmpData = data.getComponent(i);
					if (tmpData.getMinAddress().equals(addr)) {
						list.add(tmpData);
					}
					if (tmpData.getNumComponents() > 0) {
						addOpenData(list, tmpData, addr);
					}
				}
			}
			else { // Structure and DynamicDataType
				List<Data> dataList = data.getComponentsContaining((int) addr.subtract(dataAddr));
				if (dataList != null) {
					for (Data subData : dataList) {
						// The only case where more than one subData exists is for bit-fields and zero-length data.
						// Depending upon the packing, bit-fields at different offsets may overlap
						if (subData.getMinAddress().equals(addr)) {
							list.add(subData);
						}
						if (subData.getNumComponents() > 0) {
							addOpenData(list, subData, addr);
						}
					}
				}
			}
		}
	}

	private void addUnionPostOpenData(List<Data> list, Data data, Address addr) {
		DataType dt = data.getBaseDataType();
		if (dt instanceof Union) {
			Address dataAddr = data.getMinAddress();
			if (openCloseMgr.isDataOpen(data)) {
				int openIndex = openCloseMgr.getOpenDataIndex(data);
				int i = openIndex;
				int numComps = ((Union) dt).getNumComponents();
				if (i < 0) {
					i = numComps;
				}
				for (; i < numComps; i++) {
					Data tmpData = data.getComponent(i);
					if (tmpData.getNumComponents() > 0) {
						addUnionPostOpenData(list, tmpData, addr);
					}
					if ((i > openIndex) && data.getMaxAddress().equals(addr)) {
						list.add(tmpData);
					}
				}
			}
		}
	}

	@Override
	public boolean isOpen(Data data) {
		return openCloseMgr.isDataOpen(data);
	}

	@Override
	public void toggleOpen(Data data) {
		openCloseMgr.toggleDataOpen(data);
	}

	@Override
	public void setFunctionVariablesOpen(Address functionEntry, boolean open) {
		openCloseMgr.setFunctionVariablesOpen(functionEntry, open);
	}

	@Override
	public void setAllFunctionVariablesOpen(boolean open) {
		openCloseMgr.setAllFunctionVariablesOpen(open);
	}

	@Override
	public boolean areFunctionVariablesOpen(Address functionEntry) {
		return openCloseMgr.isFunctionVariablesOpen(functionEntry);
	}

	@Override
	public boolean isFunctionOpen(Address functionEntry) {
		return openCloseMgr.isFunctionOpen(functionEntry);
	}

	@Override
	public void setFunctionOpen(Address functionEntry, boolean b) {
		openCloseMgr.setFunctionOpen(functionEntry, b);
	}

	@Override
	public void setAllFunctionsOpen(boolean selected) {
		openCloseMgr.setAllFunctionsOpen(selected);
	}

	@Override
	public void openAllData(Data data, TaskMonitor monitor) {
		openCloseMgr.openDataRecursively(data, monitor);
	}

	@Override
	public void closeAllData(Data data, TaskMonitor monitor) {
		openCloseMgr.closeDataRecursively(data, monitor);
	}

	@Override
	public void openAllData(AddressSetView addresses, TaskMonitor monitor) {
		openCloseMgr.openAllData(program, addresses, monitor);
	}

	@Override
	public void closeAllData(AddressSetView addresses, TaskMonitor monitor) {
		openCloseMgr.closeAllData(program, addresses, monitor);
	}

	@Override
	public void closeData(Data data) {
		openCloseMgr.closeData(data);
	}

	@Override
	public boolean openData(Data data) {
		openCloseMgr.openData(data);
		return true;
	}

	protected void notifyDataChanged(boolean updateImmediately) {
		layoutCache.clear();

		for (ListingModelListener listener : listeners) {
			listener.dataChanged(updateImmediately);
		}
	}

	private void notifyModelSizeChanged() {
		layoutCache.clear();

		for (ListingModelListener listener : listeners) {
			listener.modelSizeChanged();
		}
	}

	@Override
	public void formatModelChanged(FieldFormatModel model) {
		notifyModelSizeChanged();
	}

	@Override
	public void addListener(ListingModelListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeListener(ListingModelListener listener) {
		listeners.remove(listener);
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public boolean isClosed() {
		return program.isClosed();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (program.isClosed()) {
			return;
		}

		boolean updateImmediately = ev.numRecords() <= 5;
		notifyDataChanged(updateImmediately);
	}

	@Override
	public AddressSet adjustAddressSetToCodeUnitBoundaries(AddressSet addressSet) {
		if (program == null) {
			return addressSet;
		}
		List<AddressRange> list = addressSet.toList();
		for (AddressRange range : list) {
			Address minAddr = range.getMinAddress();
			Address maxAddr = range.getMaxAddress();
			CodeUnit cu = program.getListing().getCodeUnitContaining(minAddr);
			if (cu != null) {
				Address minCuAddr = cu.getMinAddress();
				if (!minCuAddr.equals(minAddr)) {
					addressSet.addRange(minCuAddr, minAddr);
				}
			}
			cu = program.getListing().getCodeUnitContaining(maxAddr);
			if (cu != null) {
				Address maxCuAddr = cu.getMaxAddress();
				if (!maxCuAddr.equals(maxAddr)) {
					addressSet.addRange(maxAddr, maxCuAddr);
				}
			}
		}
		return addressSet;
	}

	private class LayoutCache {

		private LRUMap<Address, Layout> cache = new LRUMap<>(10);
		private LRUMap<Address, Layout> gapCache = new LRUMap<>(10);

		void clear() {
			cache.clear();
			gapCache.clear();
		}

		Layout get(Address addr, boolean isGapAddress) {
			if (isGapAddress) {
				return gapCache.get(addr);
			}
			return cache.get(addr);
		}

		void put(Address addr, Layout layout, boolean isGapAddress) {
			if (isGapAddress) {
				gapCache.put(addr, layout);
			}
			else {
				cache.put(addr, layout);
			}
		}
	}

	@Override
	public ListingModel copy() {
		ProgramBigListingModel model = new ProgramBigListingModel(program, formatMgr);
		model.openCloseMgr = openCloseMgr;
		return model;
	}

}
