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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.awt.Color;
import java.util.*;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A class that 'describes' a {@link ProgramLocation}.  The descriptor is also based upon the
 * program to which the location belongs and requires the {@link PluginTool} to which the
 * program belongs.
 * <p>
 * A location descriptor 'knows' how to identify the 'thing' at the given location and how to get
 * addresses that reference that 'thing'.  For example, if the program location is based on a
 * {@link DataType}, then the descriptor knows how to find all places that datatype is applied.
 * Alternatively, if the program location is a label in an operand field, then the descriptor
 * will provide addresses of places that reference the item to which the label is attached and
 * <b>not</b> the given location.
 * <p>
 * Location descriptors also 'know' how to highlight the relevant reference points that
 * refer to the 'thing' that the descriptor is describing.  For example, if the program location
 * is based on a datatype, then all applied datatypes will be highlighted.
 */
public abstract class LocationDescriptor {
	protected Highlight[] EMPTY_HIGHLIGHTS = new Highlight[0];

	/** This is the location from which the query was made */
	protected ProgramLocation programLocation;

	/**
	 * FYI: This list contains no duplicates, as it was built from a set.
	 */
	protected List<LocationReference> referenceAddressList;

	/**
	 * A special comparator that allows us to find a LocationReference from a given address.
	 */
	private Comparator<Object> addressToLocationReferenceComparator = new Comparator<Object>() {
		@Override
		public int compare(Object o1, Object o2) {
			return toAddress(o1).compareTo(toAddress(o2));
		}

		private Address toAddress(Object obj) {
			if (obj instanceof Address) {
				return (Address) obj;
			}
			LocationReference ref = (LocationReference) obj;
			return ref.getLocationOfUse();
		}
	};

	/** This is the address of the thing to which we are trying to find references */
	protected Address homeAddress;
	protected String label;
	protected Program program;
	protected ChangeListener modelFreshnessListener;

	protected boolean useDynamicSearching = true;

	LocationDescriptor(ProgramLocation programLocation, Program program) {
		this.programLocation = programLocation;
		this.program = program;
	}

	ProgramLocation getLocation() {
		return programLocation;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + ": " + label;
	}

	protected boolean domainObjectChanged(DomainObjectChangedEvent changeEvent) {
		if (getHomeAddress() == null) {
			return true;
		}

		for (int i = 0; i < changeEvent.numRecords(); i++) {
			DomainObjectChangeRecord domainObjectRecord = changeEvent.getChangeRecord(i);
			int eventType = domainObjectRecord.getEventType();

			switch (eventType) {
				case ChangeManager.DOCR_MEMORY_BLOCK_MOVED:
				case ChangeManager.DOCR_MEMORY_BLOCK_REMOVED:
					if (program.getMemory().contains(getHomeAddress())) {
						checkForAddressChange(domainObjectRecord);
						return true;
					}
					break;
				case ChangeManager.DOCR_SYMBOL_ADDED:
				case ChangeManager.DOCR_SYMBOL_RENAMED:
				case ChangeManager.DOCR_SYMBOL_REMOVED:
					checkForAddressChange(domainObjectRecord);
					return true;
				case ChangeManager.DOCR_MEM_REFERENCE_ADDED:
					ProgramChangeRecord changeRecord = (ProgramChangeRecord) domainObjectRecord;
					Reference ref = (Reference) changeRecord.getNewValue();
					if (refersToAddress(ref, getHomeAddress())) {
						checkForAddressChange(domainObjectRecord);
						return true;
					}
					break;
				case ChangeManager.DOCR_MEM_REFERENCE_REMOVED:
					changeRecord = (ProgramChangeRecord) domainObjectRecord;
					ref = (Reference) changeRecord.getOldValue();
					if (refersToAddress(ref, getHomeAddress())) {
						checkForAddressChange(domainObjectRecord);
						return true;
					}
					break;
				case ChangeManager.DOCR_SYMBOL_ASSOCIATION_ADDED:
				case ChangeManager.DOCR_SYMBOL_ASSOCIATION_REMOVED:
					changeRecord = (ProgramChangeRecord) domainObjectRecord;
					ref = (Reference) changeRecord.getObject();
					if (refersToAddress(ref, getHomeAddress())) {
						checkForAddressChange(domainObjectRecord);
						return true;
					}
					break;
				case DomainObject.DO_OBJECT_RESTORED:
					checkForAddressChange(domainObjectRecord);
					return true;
			}
		}

		return false;
	}

	// see if the change is in this descriptors group of reference addresses
	protected boolean checkForAddressChange(DomainObjectChangeRecord changeRecord) {
		if (changeRecord instanceof ProgramChangeRecord) {
			Address address = ((ProgramChangeRecord) changeRecord).getStart();
			if (referenceAddressList == null) {
				return false;
			}

			boolean removed = removeReferencesFromAddress(address);

			if (modelFreshnessListener != null) {
				modelFreshnessListener.stateChanged(new ChangeEvent(this));
			}
			return removed;
		}

		int eventType = changeRecord.getEventType();
		if (eventType == DomainObject.DO_OBJECT_RESTORED) {
			// we cannot tell which addresses were effected, so the data *may* be stale
			if (modelFreshnessListener != null) {
				modelFreshnessListener.stateChanged(new ChangeEvent(this));
			}
			return true;
		}
		return false;
	}

	protected boolean refersToAddress(Reference reference, Address address) {
		Address toAddress = reference.getToAddress();
		return toAddress.equals(address);
	}

	protected boolean removeReferencesFromAddress(Address address) {
		int result = Collections.binarySearch(referenceAddressList, address,
			addressToLocationReferenceComparator);
		if (result < 0) {
			return false;
		}

		// we may have multiple references from the same address (if not, then simplify this code)
		while (result >= 0) {
			referenceAddressList.remove(result);
			result = Collections.binarySearch(referenceAddressList, address,
				addressToLocationReferenceComparator);
		}

		return true;
	}

	protected boolean referencesContain(Address address) {
		if (address == null) {
			return false;
		}

		if (referenceAddressList == null) {
			return false;
		}

		int result = Collections.binarySearch(referenceAddressList, address,
			addressToLocationReferenceComparator);
		return result >= 0;
	}

	/**
	 * A convenience method to examine the highlight object to determine how to get an address
	 * for that object, or null if the object is not of a known type.
	 * @param object The object to examine.
	 * @return the highlight object to determine how to get an address for that object
	 */
	protected Address getAddressForHighlightObject(Object object) {
		if (object instanceof CodeUnit) {
			return ((CodeUnit) object).getMinAddress();
		}
		else if (object instanceof Function) {
			return ((Function) object).getEntryPoint();
		}
		else if (object instanceof Variable) {
			Variable variable = (Variable) object;
			return variable.getFunction().getEntryPoint();
		}
		return null;
	}

	/**
	 * Returns true if the given address is in the set of this location descriptor's
	 * reference addresses or if it matches the home address.
	 * @param address The address for which to search.
	 * @return true if the given address is in the set of this location descriptor's
	 * reference addresses or if it matches the home address.
	 */
	protected boolean isInAddresses(Address address) {
		return referencesContain(address) || getHomeAddress().equals(address);
	}

	Program getProgram() {
		return program;
	}

	Address getHomeAddress() {
		return homeAddress;
	}

	/**
	 * Returns a generic {@link ProgramLocation} based upon the <tt>program</tt> and  
	 * <tt>homeAddress</tt> of this <tt>LocationDescriptor</tt>.  Subclasses should override this 
	 * method to return more specific addresses.
	 * 
	 * @return a generic ProgramLocation.
	 */
	ProgramLocation getHomeLocation() {
		return new ProgramLocation(program, homeAddress);
	}

	public String getLabel() {
		return label;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (obj == null) {
			return false;
		}

		Class<? extends Object> clazz = obj.getClass();
		if (getClass() != clazz) {
			return false;
		}

		LocationDescriptor otherDescriptor = (LocationDescriptor) obj;
		return label.equals(otherDescriptor.label) && (program == otherDescriptor.program) &&
			homeAddress.equals(otherDescriptor.homeAddress) &&
			programLocation.getAddress().equals(otherDescriptor.programLocation.getAddress());
	}

	@Override
	public int hashCode() {
		return label.hashCode() + program.hashCode() + homeAddress.hashCode() +
			programLocation.getAddress().hashCode();
	}

	public void dispose() {
		referenceAddressList.clear();
		modelFreshnessListener = null;
	}

	/**
	 * Returns the highlights for the references this descriptor is representing.
	 * @param text The text of the current item being rendered.
	 * @param obj The object associated with the text being rendered (e.g., CodeUnit).
	 * @param fieldFactoryClass The class that created the field being rendered.
	 * @param highlightColor The color to use for highlighting.
	 * @return An array of highlights to render for the given <tt>text</tt>
	 */
	abstract Highlight[] getHighlights(String text, Object obj,
			Class<? extends FieldFactory> fieldFactoryClass, Color highlightColor);

	/**
	 * Subclasses must implement this method in order to get location references in their
	 * implementation-specific way.
	 * @param accumulator the datastructure into which results will be incrementally placed
	 * @param monitor A monitor to report progress or cancel the gathering of addresses.
	 * @throws CancelledException if the monitor is cancelled while this method is performing its
	 *         work
	 */
	protected abstract void doGetReferences(Accumulator<LocationReference> accumulator,
			TaskMonitor monitor) throws CancelledException;

	/**
	 * Returns a descriptive category name for this location descriptor.  This is used for 
	 * display in a popup menu. 
	 * 
	 * @return a descriptive category name for this location descriptor
	 */
	public String getTypeName() {
		return label;
	}

	private void getReferenceAddressSet(Accumulator<LocationReference> accumulator,
			TaskMonitor monitor, boolean reload) throws CancelledException {

		if (referenceAddressList == null || reload) {
			doGetReferences(accumulator, monitor);

			// put into list so that we can later perform fast lookups of Addresses
			referenceAddressList = new ArrayList<>(accumulator.get());
			Collections.sort(referenceAddressList);
			return;
		}

		accumulator.addAll(referenceAddressList);
	}

	/**
	 * Gets all location references for the given descriptor, loading them if not already loaded.
	 * 
	 * @param accumulator the datastructure into which will be placed a collection of 
	 * 		  location references that reference the location this descriptor is representing.
	 * @param monitor A monitor to report progress or cancel the gathering of addresses.
	 * @param reload True signals to perform a new search for reference addresses; false will
	 *        use the existing data if it has been loaded.
	 * @throws CancelledException if the monitor is cancelled while this method is performing its
	 *         work
	 */
	void getReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor,
			boolean reload) throws CancelledException {
		getReferenceAddressSet(accumulator, monitor, reload);
	}

	/**
	 * When true, the search algorithm will use dynamic searching when possible, which is to 
	 * not only find references that are already created, but to also use external tools to 
	 * locate potential references. 
	 * 
	 * @param useDynamicSearching true to perform dynamic searching
	 */
	void setUseDynamicSearching(boolean useDynamicSearching) {
		this.useDynamicSearching = useDynamicSearching;
	}

	/**
	 * Sets a listener on this descriptor that will be notified when the references contained
	 * in this descriptor may no longer be accurate.  For example, the listener will be called
	 * when an undo or redo is performed in Ghidra.
	 * @param modelChangeListener The listener to add.
	 */
	void setModelFreshnessListener(ChangeListener modelFreshnessListener) {
		this.modelFreshnessListener = modelFreshnessListener;
	}
}
