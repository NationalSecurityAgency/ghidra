/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.symbol;

/**
 * Interface to define methods that are called when references are
 * added or removed.
 */
public interface ReferenceListener {

	/**
	 * Notification that the given memory reference has been added.
	 * @param ref the reference that was added.
	 */	
	public void memReferenceAdded(Reference ref);

	/**
	 * Notification that the given memory reference has bee removed.
	 * @param ref the reference that was removed.
	 */		
	public void memReferenceRemoved(Reference ref);
	
	/**
	 * Notification that the reference type on the given memory reference
	 * has changed.
	 * @param newRef the reference with the new reference type.
	 * @param oldRef the reference with the old reference type. 
	 */	
	public void memReferenceTypeChanged(Reference newRef, Reference oldRef);

	/**
	 * Notification that the given memory reference has been set as
	 * the primary reference.
	 * @param ref the reference that is now primary.
	 */		
	public void memReferencePrimarySet(Reference ref);

	/**
	 * Notification that the given memory reference is no longer the primary
	 * reference.
	 * @param ref the reference that was primary but now is not.
	 */		
	public void memReferencePrimaryRemoved(Reference ref);
	
	/**
	 * Notification that the given stack reference has been added.
	 * @param ref the stack reference that was added.
	 */		
	public void stackReferenceAdded(Reference ref);

	/**
	 * Notification tbat the given stack reference has been removed.
	 * @param ref The stack reference that was removed
	 */		
	public void stackReferenceRemoved(Reference ref);

	/**
	 * Notification that the given external reference has been added.
	 * @param ref the external reference that was added.
	 */		
	public void externalReferenceAdded(Reference ref);

	/**
	 * Notification that the given external reference has been removed.
	 * @param ref the external reference that was removed.
	 */		
	public void externalReferenceRemoved(Reference ref);

	/**
	 * Notification that the external program name in the reference
	 * has changed.
	 * @param ref the external reference with its new external name.
	 */		
	public void externalReferenceNameChanged(Reference ref);
}
