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
package ghidra.app.plugin.core.searchtext.databasesearcher;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.util.ProgramLocation;

import java.util.*;
import java.util.regex.Pattern;

public abstract class ProgramDatabaseFieldSearcher {
	protected final Pattern pattern;
	protected final boolean forward;
	private Address currentAddress;
	private ProgramLocation startLocation;
	private List<ProgramLocation> matchesForCurrentAddress = new LinkedList<ProgramLocation>();

	protected ProgramDatabaseFieldSearcher(Pattern pattern, boolean forward, ProgramLocation startLoc, AddressSetView set) {
		this.pattern = pattern;
		this.forward = forward;
		this.startLocation = startLoc;
		
		if (forward && set != null && !set.isEmpty() && startLoc != null && 
				!set.getMinAddress().equals(startLoc.getAddress())) {
			throw new IllegalArgumentException("Start location and addressSet are inconsistent!");
		}
		if (!forward && set != null && !set.isEmpty() && startLoc != null && 
				!set.getMaxAddress().equals(startLoc.getAddress())) {
			throw new IllegalArgumentException("Start location and addressSet are inconsistent!");
		}

	}
	private void initialize() {
		currentAddress = doAdvance(matchesForCurrentAddress);
		trimMatchesForStartLocation( );
	}
	private Address doAdvance(List<ProgramLocation> currentMatches) {
		Address address = advance(matchesForCurrentAddress);
        if (!forward) {
        	Collections.reverse( matchesForCurrentAddress );
        }
        return address;
	}
	protected abstract Address advance(List<ProgramLocation> currentMatches);
	
	public Address getNextSignificantAddress( Address address ) {
		if (address == null) {
			initialize();
			return currentAddress;
		}
		if (currentAddress == null) {  // we have no more records in our iterator.
			return null;
		}
		if (currentAddress.equals( address )) {		// we need to move to the next record
			currentAddress = doAdvance(matchesForCurrentAddress);
		}
		return currentAddress;
	}

	public ProgramLocation getMatch() {
		return matchesForCurrentAddress.remove( 0 );
	}
	
	public boolean hasMatch( Address address ) {
		if (!address.equals(currentAddress)) {
			return false;
		}
		return !matchesForCurrentAddress.isEmpty();
	}	

	private void trimMatchesForStartLocation( ) {
		if (startLocation == null) {
			return;
		}
		if (!startLocation.getAddress().equals( currentAddress )) {
			return;
		}
		Iterator<ProgramLocation> it = matchesForCurrentAddress.iterator();
		while(it.hasNext()) {
			ProgramLocation programLoc = it.next();
			int compareVal = startLocation.compareTo( programLoc );
			if ((forward && compareVal >=0) ||
				(!forward && compareVal <=0 )) {	
					it.remove();
			}
		}
	}
}
