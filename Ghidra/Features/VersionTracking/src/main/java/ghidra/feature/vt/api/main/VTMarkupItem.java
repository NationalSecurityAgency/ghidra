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
package ghidra.feature.vt.api.main;

import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;

public interface VTMarkupItem {
	public static final String USER_DEFINED_ADDRESS_SOURCE = "User Defined";
	public static final String FUNCTION_ADDRESS_SOURCE = "Function";
	public static final String DATA_ADDRESS_SOURCE = "Data";

	/**
	 * Returns true if this markup item can be applied.
	 * @return true if this markup item can be applied.
	 */
	public boolean canApply();

	/**
	 * Returns true if this markup item can be unapplied.
	 * @return true if this markup item can be unapplied.
	 */
	public boolean canUnapply();

	/**    
	 * Applies this markup item using the given action at the give address.  The destination 
	 * address and the address source must be set prior to calling this method.
	 * 
	 * @param applyAction the type of apply action to take when applying the given markup item
	 * @throws VersionTrackingApplyException if an error occurred while attempting to apply the
	 * markup item.
	 */
	public void apply(VTMarkupItemApplyActionType applyAction, ToolOptions options)
			throws VersionTrackingApplyException;

	/**
	 * Returns the value in the destination program back to its original value.
	 * @throws VersionTrackingApplyException if an error occurred while attempting to unapply the
	 * markup item.
	 */
	public void unapply() throws VersionTrackingApplyException;

	/**
	 * Sets the default destination address for this item.  This address will not be saved, as it
	 * is considered a temporary address value.  Further, this value is intended to be a 
	 * "best guess" as to what the destination address should be.
	 * <p>
	 * Users should not call this method, but should instead call 
	 * {@link #setDestinationAddress(Address)}.
	 * 
	 * @param address the address to set.
	 * @param addressSource the source of the address.  This will be the name of a
	 *        {@link VTProgramCorrelator} when a correlator is used to populate default address
	 *        values.
	 *  @see #setDestinationAddress(Address)
	 */
	public void setDefaultDestinationAddress(Address address, String addressSource);

	/**
	 * Sets the actual destination address for the markup item.  This method differs from
	 * {@link #setDefaultDestinationAddress(Address, String)} in that the address passed to this
	 * method will be saved. 
	 * <p>
	 * The {@link #getDestinationAddressSource()} will return {@link #USER_DEFINED_ADDRESS_SOURCE}
	 * when a valid destination address is set via this method.
	 * <p>
	 * To clear the destination address you may pass <tt>null</tt> to this method.
	 * 
	 * @param address the new destination address for the item.
	 * @throws IllegalStateException if this method is called on an applied markup item (you 
	 *         can use {@link #canUnapply()} to know if this item is applied).
	 * @see #setDefaultDestinationAddress(Address, String)
	 */
	public void setDestinationAddress(Address address);

	/**
	 * Returns the editable status of this markup item's destination address.
	 *  
	 * @return the editable status of this markup item's destination address.
	 * @see #setDestinationAddress(Address, String)
	 */
	public VTMarkupItemDestinationAddressEditStatus getDestinationAddressEditStatus();

	/**
	 * Sets a considered status on this item without applying this item.  This is useful to 
	 * indicate that you <b>considered</b> this item and have decided not to apply it, with 
	 * some indication as to why.
	 * <p>
	 * To clear the considered status pass {@link VTMarkupItemConsideredStatus#UNCONSIDERED}.
	 * <p>
	 * If the status was an "applied" status, then an exception will be thrown.  To determine if
	 * an item is applied you can use {@link #canUnapply()}.
	 * 
	 * @param status The <b>considered</b> status to set
	 * @throws IllegalStateException if you call this method on an applied item
	 * @see #setUnconsidered()
	 */
	public void setConsidered(VTMarkupItemConsideredStatus status);

	/**
	 * Returns the status of this markup item. 
	 * @return  the status of this markup item.
	 */
	public VTMarkupItemStatus getStatus();

	/** 
	 * Returns an optional description of the current markup item status.  For example, if there
	 * status is {@link VTMarkupItemStatus#FAILED_APPLY}, then this method should return a 
	 * description of the failure.
	 */
	public String getStatusDescription();

	/**
	 * Returns the VTAssocation that generated this markup item.
	 * @return  the VTAssocation that generated this markup item.
	 */
	public VTAssociation getAssociation();

	/**
	 * Returns the address in the source program for this association.
	 * @return the address in the source program for this association.
	 */
	public Address getSourceAddress();

	/**
	 * Returns the field specific program location in the source program for this association.
	 * @return the field specific program location in the source program for this association.
	 */
	public ProgramLocation getSourceLocation();

	/**
	 * Returns a Stringable that represents the value of the markup item in the source program.
	 * @return a Stringable that represents the value of the markup item in the source program.
	 */
	public Stringable getSourceValue();

	/**
	 * Returns the address in the destination program for this association.
	 * @return the address in the destination program for this association.
	 */
	public Address getDestinationAddress();

	/**
	 * Returns the field specific program location in the destination program for this association.
	 * @return the field specific program location in the destination program for this association.
	 */
	public ProgramLocation getDestinationLocation();

	/**
	 * Returns a string that indicates the origin of the destination address. Typically, it is
	 * determined either by an algorithm or the user.
	 * @return  a string that indicates the origin of the destination address.
	 */
	public String getDestinationAddressSource();

	/**
	 * Returns a Stringable that represents the current value of the markup item in the destination
	 * program.
	 * @return a Stringable that represents the current value of the markup item in the destination
	 * program.
	 */
	public Stringable getCurrentDestinationValue();

	/**
	 * Returns a Stringable that represents the original value of the markup item in the destination
	 * program.
	 * @return a Stringable that represents the original value of the markup item in the destination
	 * program.
	 */
	public Stringable getOriginalDestinationValue();

	/**
	 * Returns true if this markupItem supports an apply for the given apply action type.
	 * @param actionType the VTMarkupITemApplyActionType to test.
	 * @return true if this markup item can be applied using the given action type.
	 */
	public boolean supportsApplyAction(VTMarkupItemApplyActionType actionType);

	/**
	 * Returns the VTMarkupType for this markup Item.  VTMarkup types include comments, labels, 
	 * function names, etc.
	 * @return the VTMarkupType for this markup Item.
	 */
	public VTMarkupType getMarkupType();

}
