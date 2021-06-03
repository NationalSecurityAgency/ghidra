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

import java.awt.Dimension;
import java.math.BigInteger;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.util.AddressBasedIndexMapper;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.task.SwingUpdateManager;

public class ListingModelAdapter implements LayoutModel, ListingModelListener {
	private static Class<?> defaultFieldFactoryClass = AddressFieldFactory.class;

	private final ListingModel model;
	private WeakSet<LayoutModelListener> listeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();
	private AddressIndexMap addressToIndexMap;
	private SwingUpdateManager updateMgr;

	private Dimension preferredViewSize;

	public ListingModelAdapter(ListingModel bigListingModel) {
		this.model = bigListingModel != null ? bigListingModel : new EmptyListingModel();
		addressToIndexMap = new AddressIndexMap(model.getAddressSet());
		removeUnviewableAddressRanges();
		model.addListener(this);

		updateMgr = new SwingUpdateManager(500, 5000, () -> {
			if (!model.isClosed()) {
				resetIndexMap();
				for (LayoutModelListener listener : listeners) {
					listener.dataChanged(BigInteger.ZERO, addressToIndexMap.getIndexCount());
				}
				preferredViewSize = null;
			}
		});
	}

	@Override
	public void flushChanges() {
		if (updateMgr.hasPendingUpdates()) {
			updateMgr.updateNow();
		}
	}

	@Override
	public void addLayoutModelListener(LayoutModelListener listener) {
		listeners.add(listener);
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		Address address = addressToIndexMap.getAddress(index);
		if (address == null) {
			return null;
		}
		Address nextAddress = model.getAddressAfter(address);
		if (nextAddress == null) {
			return null;
		}
		BigInteger nextIndex = addressToIndexMap.getIndexAtOrAfter(nextAddress);
		if (nextIndex == null) {
			nextIndex = index.add(BigInteger.ONE);
		}
		return nextIndex;
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		if (index.compareTo(BigInteger.ZERO) <= 0) {
			return null;
		}
		BigInteger indexCount = addressToIndexMap.getIndexCount();
		if (index.compareTo(indexCount) >= 0) {
			return indexCount.subtract(BigInteger.ONE);
		}
		Address address = addressToIndexMap.getAddress(index);
		if (address == null) {
			return null;
		}
		Address previousAddress = model.getAddressBefore(address);
		if (previousAddress == null) {
			return null;
		}
		BigInteger previousIndex = addressToIndexMap.getIndex(previousAddress);
		if (previousIndex == null) {
			if (index.equals(BigInteger.ZERO)) {
				return null;
			}
			previousIndex = index.subtract(BigInteger.ONE);
		}
		return previousIndex;
	}

	@Override
	public Layout getLayout(BigInteger index) {
		Address address = addressToIndexMap.getAddress(index);
		if (address == null) {
			return null;
		}
		return model.getLayout(address, addressToIndexMap.isGapIndex(index));
	}

	@Override
	public Dimension getPreferredViewSize() {
		if (preferredViewSize == null) {
			preferredViewSize = computePreferredViewSize();
		}
		return preferredViewSize;
	}

	private Dimension computePreferredViewSize() {
		BigInteger indexCount = getNumIndexes();
		int preferredHeight = indexCount.compareTo(BigInteger.valueOf(100)) > 0 ? 500
				: computePreferredHeight(indexCount.intValue());
		return new Dimension(model.getMaxWidth(), preferredHeight);
	}

	private int computePreferredHeight(int n) {
		int height = 0;
		for (int i = 0; i < n; i++) {
			Layout layout = getLayout(BigInteger.valueOf(i));
			if (layout != null) {
				height += layout.getHeight();
			}
		}

		return height;
	}

	@Override
	public BigInteger getNumIndexes() {
		return addressToIndexMap.getIndexCount();
	}

	@Override
	public boolean isUniform() {
		return false;
	}

	@Override
	public void removeLayoutModelListener(LayoutModelListener listener) {
		listeners.remove(listener);
	}

	public void dispose() {
		updateMgr.dispose();
		model.dispose();
	}

	@Override
	public void dataChanged(boolean updateImmediately) {
		if (updateImmediately) {
			updateMgr.updateNow();
		}
		else {
			updateMgr.update();
		}
	}

	@Override
	public void modelSizeChanged() {
		preferredViewSize = null;
		for (LayoutModelListener listener : listeners) {
			listener.modelSizeChanged(IndexMapper.IDENTITY_MAPPER);
		}
	}

	/**
	 * Translates the given ProgramLocation into a FieldLocation.  Attempts to find a
	 * field that can exactly find a match for the program location.  Otherwise, it
	 * will return a fieldLocation to the default field or beginning of the line.
	 * @param location the ProgramLocation to translate.
	 * @return a FieldLocation for the ProgramLocation or null if none can be found.
	 */
	public FieldLocation getFieldLocation(ProgramLocation location) {

		// try to find a layout for an exact address first
		FieldLocation floc = getFieldLocation(location.getByteAddress(), location, false);
		if (floc != null) {
			return floc;
		}

		// try the code unit boundary address
		floc = getFieldLocation(location.getAddress(), location, false);
		if (floc != null) {
			return floc;
		}
		return getFieldLocation(location.getAddress(), location, true);
	}

	/**
	 * Attempts to find a field location for the given address from the given program location
	 * @param address the address to try and get a layout for.
	 * @param location the location contains other information needed to generate a field
	 * location
	 * @param useDefaultLocation if true, will return a generic location for this address
	 * if no field has a specific match.  Otherwise, will return null if no fields have
	 * an exact match.
	 * @return a field location for the given address.
	 */
	private FieldLocation getFieldLocation(Address address, ProgramLocation location,
			boolean useDefaultLocation) {

		BigInteger index = addressToIndexMap.getIndex(address);
		Layout layout = getLayout(index);
		if (layout == null) {
			index = getLayoutWithinCodeUnit(address);
			layout = getLayout(index);
		}

		if (layout == null) {
			return null;
		}

		if (layout.getNumFields() == 0) {
			return null;
		}

		int defaultFieldIndex = 0;
		for (int i = 0; i < layout.getNumFields(); i++) {
			ListingField f = (ListingField) layout.getField(i);
			FieldFactory factory = f.getFieldFactory();
			if (factory.getClass() == defaultFieldFactoryClass) {
				defaultFieldIndex = i;
			}

			// this method only returns a location if all information matches.
			FieldLocation floc = factory.getFieldLocation(f, index, i, location);
			if (floc != null) {
				return floc;
			}
		}

		// if no exact match and using defaults is on, just return a basic location for the
		// default field
		if (useDefaultLocation) {
			return new FieldLocation(index, defaultFieldIndex, 0, 0);
		}
		return null;
	}

	private BigInteger getLayoutWithinCodeUnit(Address address) {
		CodeUnit cu = model.getProgram().getListing().getCodeUnitContaining(address);
		if (cu == null) {
			return null;
		}

		Address min = cu.getMinAddress();
		while (address.compareTo(min) > 0) {
			address = address.subtract(1);
			Layout layout = model.getLayout(address, false);
			if (layout != null) {
				return addressToIndexMap.getIndex(address);
			}
		}
		return null;
	}

	public ProgramLocation getProgramLocation(FieldLocation floc) {
		if (floc == null) {
			return null;
		}

		BigInteger index = floc.getIndex();
		Layout layout = getLayout(index);
		if (layout == null) {
			Address addr = addressToIndexMap.getAddress(index);
			return addr != null ? new ProgramLocation(model.getProgram(), addr) : null;
		}

		ListingField bf = null;

		if (floc.getFieldNum() >= layout.getNumFields()) {
			bf = (ListingField) layout.getField(0);
		}
		else {
			bf = (ListingField) layout.getField(floc.getFieldNum());
		}

		return getProgramLocation(floc, bf);
	}

	public ProgramLocation getProgramLocation(FieldLocation location, Field field) {
		ListingField lf = (ListingField) field;
		if (lf != null) {
			FieldFactory factory = lf.getFieldFactory();

			ProgramLocation pLoc =
				factory.getProgramLocation(location.getRow(), location.getCol(), lf);

			if (pLoc == null) {
				Address addr = addressToIndexMap.getAddress(location.getIndex());
				Program p = model.getProgram();
				if (addr != null && p != null) {
					pLoc = new ProgramLocation(p, addr);
				}
			}
			return pLoc;
		}
		return null;
	}

	public ProgramSelection getAllProgramSelection() {
		Program program = model.getProgram();
		AddressFactory factory = program == null ? null : program.getAddressFactory();
		return new ProgramSelection(factory, model.getAddressSet());
	}

	// This method works for structures inside unions, but doesn't handle data
	// structures changing out from under it.
	public ProgramSelection getProgramSelection(FieldSelection selection) {
		AddressSet addrSet = addressToIndexMap.getAddressSet(selection);
		if (addrSet.getNumAddressRanges() == 1) {
			ProgramSelection ps = getInteriorSelection(selection);
			if (ps != null) {
				return ps;
			}
		}
		Program program = model.getProgram();
		addrSet = model.adjustAddressSetToCodeUnitBoundaries(addrSet);
		AddressFactory factory = program == null ? null : program.getAddressFactory();
		return new ProgramSelection(factory, addrSet);
	}

	// this methods does NOT work for structures inside of unions, but handles structures
	// changing out from under it very well.
	private ProgramSelection getInteriorSelection(FieldSelection sel) {
		Program program = model.getProgram();
		if (program == null || sel.getNumRanges() != 1) {
			return null;
		}
		FieldRange range = sel.getFieldRange(0);
		ProgramLocation loc1 = getProgramLocation(
			new FieldLocation(range.getStart().getIndex(), range.getStart().getFieldNum(), 0, 0));
		BigInteger endIndex = range.getEnd().getIndex();
		int endField = range.getEnd().getFieldNum();
		if (endField == 0) {
			endIndex = endIndex.subtract(BigInteger.ONE);
			Layout layout = getLayout(endIndex);
			if (layout != null) {
				endField = layout.getNumFields() - 1;
			}
		}
		else {
			endField--;
		}
		ProgramLocation loc2 = getProgramLocation(new FieldLocation(endIndex, endField, 0, 0));
		if (loc1 == null || loc2 == null) {
			return null;
		}
		int[] path1 = loc1.getComponentPath();
		int[] path2 = loc2.getComponentPath();
		if (path1 == null || path2 == null) {
			return null;
		}
		if (path1.length > path2.length) {
			return null;
		}
		if (path1.length == 0) {
			return null;
		}
		for (int i = 0; i < path1.length - 1; i++) {
			if (path1[i] != path2[i]) {
				return null;
			}
		}
		Address min = loc1.getAddress();
		Data data1 = program.getListing().getDataContaining(loc1.getAddress());
		Data data2 = program.getListing().getDataContaining(loc2.getAddress());
		if (!data1.equals(data2)) {
			return null;
		}
		Data subData2 = data2.getComponent(path2);
		Data parent = subData2.getParent();
		DataType dt = parent.getBaseDataType();
		if (dt instanceof Array) {
			return selectHighestLevelArray(parent);
		}
		Address max2 = subData2.getMaxAddress();
		if (path1.length != path2.length) {
			Data subData1 = data2.getComponent(path1);
			Address max1 = subData1.getMaxAddress();
			if (!max1.equals(max2)) {
				return null;
			}
		}

		InteriorSelection is = new InteriorSelection(loc1, loc2, min, max2);
		return new ProgramSelection(is);

	}

	private ProgramSelection selectHighestLevelArray(Data arrayData) {
		Data highestArrayData = findHighestArrayData(arrayData);
		Address min = highestArrayData.getMinAddress();
		Address max = highestArrayData.getMaxAddress();
		Program program = highestArrayData.getProgram();
		int[] componentPath = highestArrayData.getComponentPath();
		if (componentPath.length == 0) {
			return null;
		}
		ProgramLocation loc1 = new ProgramLocation(program, min, componentPath, null, 0, 0, 0);
		ProgramLocation loc2 = new ProgramLocation(program, max, componentPath, null, 0, 0, 0);
		return new ProgramSelection(new InteriorSelection(loc1, loc2, min, max));
	}

	private Data findHighestArrayData(Data arrayData) {
		Data highest = arrayData;
		Data parent = arrayData.getParent();
		while (parent != null) {
			if (parent.getBaseDataType() instanceof Array) {
				highest = parent;
			}
			parent = parent.getParent();
		}
		return highest;
	}

	protected void resetIndexMap() {
		AddressIndexMap previous = addressToIndexMap.reset();
		removeUnviewableAddressRanges();
		AddressBasedIndexMapper mapper = new AddressBasedIndexMapper(previous, addressToIndexMap);
		for (LayoutModelListener listener : listeners) {
			listener.modelSizeChanged(mapper);
		}
	}

	private boolean removeUnviewableAddressRanges() {
		boolean changed = false;
		AddressSet set = findUnviewableAddressRanges();
		while (!set.isEmpty()) {
			changed = true;
			addressToIndexMap.removeUnviewableAddressRanges(set);
			set = findUnviewableAddressRanges();
		}
		return changed;
	}

	private AddressSet findUnviewableAddressRanges() {
		// check the address every "minimum gap size" which should find any gaps
		// bigger than that gap size.  The minimum gap size is about 1% of the total
		// addresses, so this should loop about 100 times.
		BigInteger stepSize = addressToIndexMap.getMiniumUnviewableGapSize();
		BigInteger indexCount = addressToIndexMap.getIndexCount();

		AddressSet addressSet = new AddressSet();

		BigInteger index = BigInteger.ZERO;
		while (index.compareTo(indexCount) < 0) {
			checkIndex(index, addressSet);
			index = index.add(stepSize);
		}
		return addressSet;
	}

	private void checkIndex(BigInteger index, AddressSet addressSet) {
		BigInteger indexAfter = getIndexAfter(index);
		if (indexAfter == null) {
			indexAfter = addressToIndexMap.getIndexCount();
		}
		BigInteger indexBefore = getIndexBefore(index.add(BigInteger.ONE));
		if (indexBefore == null) {
			indexBefore = BigInteger.ZERO;
		}
		if (indexAfter.subtract(indexBefore)
				.compareTo(addressToIndexMap.getMiniumUnviewableGapSize()) > 0) {
			Address start = addressToIndexMap.getAddress(indexBefore.add(BigInteger.ONE));
			Address end = addressToIndexMap.getAddress(indexAfter.subtract(BigInteger.ONE));
			if (start != null && end != null &&
				start.getAddressSpace().equals(end.getAddressSpace())) {
				addressSet.add(start, end);
			}
		}
	}


	public Layout getLayout(Address addr) {
		BigInteger index = addressToIndexMap.getIndex(addr);
		return getLayout(index);
	}

	public AddressIndexMap getAddressIndexMap() {
		return addressToIndexMap;
	}

	public FieldSelection getFieldSelection(ProgramSelection selection) {
		return addressToIndexMap.getFieldSelection(selection);
	}

	/**
	 * Sets the addresses displayed by this model's listing.
	 * @param view the addresses. These must already be compatible with the program
	 * associated with this model.
	 */
	public void setAddressSet(AddressSetView view) {
		addressToIndexMap = new AddressIndexMap(view);
		removeUnviewableAddressRanges();
		modelSizeChanged();
	}

}
