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
//Searches for runs of pointers the same distance apart.
//@category Search

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import java.util.ArrayList;
import java.util.List;

public class FindRunsOfPointersScript extends GhidraScript {
	private List<PossiblePtrs> resultsArray = new ArrayList<PossiblePtrs>();
	private List<Table> tableArray = new ArrayList<Table>();
	public static final int LITTLE_ENDIAN = 0;
	public static final int BIG_ENDIAN = 1;

	@Override
	public void run() throws Exception {

		int size = currentProgram.getAddressFactory().getDefaultAddressSpace().getSize();
		if (size != 32) {
			println("This script only works on 32-bit programs.");
			return;
		}
		boolean searchNonRefd =
			askYesNo("", "Would you like to find non-referenced pointer tables?");

		Memory memory = currentProgram.getMemory();
		long distance;
		// TODO add option to work only on selection
		AddressIterator addrIter = memory.getAddresses(true);
		//println("Memory range: " + memory.getMinAddress() + " - " + memory.getMaxAddress());
		Address prevAddress = null;
		while (addrIter.hasNext() && !monitor.isCancelled()) {
			Address addr = addrIter.next();
			try {
				// get the value in address form of the bytes at address a
				int addrInt = memory.getInt(addr);
				long addrLong = addrInt & 0xffffffffL;
				Address testAddr = addr.getNewAddress(addrLong);

				if ((addrLong != 0) && (memory.contains(testAddr))) {
					if (prevAddress != null) {
						distance = addr.subtract(prevAddress);
					}
					else
						distance = 0;

					PossiblePtrs pp = new PossiblePtrs(addr, testAddr, distance);

					resultsArray.add(pp);
					//println(addr.toString() + " " + testAddr.toString() + " " + distance);
					prevAddress = addr;
				}
			}
			catch (MemoryAccessException e) {
				break;
			}
			catch (AddressOutOfBoundsException e) {
				break;
			}
		}
		// go through the list of pointers and only print out the ones with a run of the same distance between them
		// keep the one before the run and include the last one with the same distance
		//println("tableAddress distance tableSize");
		long dist = resultsArray.get(0).getDistanceFromLast();
		int tableSize = 0;
		Address topAddress = null;
		int i = 1;
		while (i < resultsArray.size() && !monitor.isCancelled()) {
			//   for(int i=1;i<resultsArray.size();i++){
			long thisDist = resultsArray.get(i).getDistanceFromLast();
			if (thisDist == dist) {
				if (tableSize == 0) {
					topAddress = resultsArray.get(i - 2).getAddrOfPtr();
					tableSize = 1;
				}
				tableSize++;
			}
			else {
				if (tableSize >= 3) {
					tableSize++;

					Address ref = findRef(topAddress, dist);
					//println(topAddress.toString() + " " + dist + " " + tableSize);	    			
					Table pointerTable = new Table(topAddress, dist, tableSize, ref);
					tableArray.add(pointerTable);
				}
				tableSize = 0;
				dist = thisDist;
			}
			i++;
		}
		// print out results
		println("Table address      Dist bet ptrs     Num ptrs       Ref found");
		for (int j = 0; j < tableArray.size(); j++) {
			Table ptrTable = tableArray.get(j);
			String refString = new String();
			if (ptrTable.getRef() != null) {
				refString = " at " + ptrTable.getRef().toString();
				println("    " + ptrTable.getTopAddr().toString() + "             " +
					ptrTable.getDistance() + "                " + ptrTable.getNumPointers() +
					"            " + refString);
			}
			else if (searchNonRefd) {
				refString = "No";
				println("    " + ptrTable.getTopAddr().toString() + "             " +
					ptrTable.getDistance() + "                " + ptrTable.getNumPointers() +
					"            " + refString);
			}
		}
		// TODO put in a navigatable table

	}

	// find the first ref starting at topAddr and working back dist - pointersize
	// once a ref is found, stop - it doesn't make much sense that there would be more than one.
	Address findRef(Address topAddress, long dist) {

		Memory memory = currentProgram.getMemory();
		Address ref = null;

		//change later to handle 64 bits too
		byte[] maskBytes = new byte[4];
		for (int i = 0; i < 4; i++) {
			maskBytes[i] = (byte) 0xff;
		}

		// search memory for the byte patterns within the range of topAddr and topAddr - dist
		// make a structure of found bytes/topAddr offset????
		boolean noRefFound = true;
		boolean tryPrevAddr = true;
		long longIndex = 0;
		while (noRefFound && tryPrevAddr) {
			Address testAddr = topAddress.subtract(longIndex);
			byte[] addressBytes = turnAddressIntoBytes(testAddr);

			//println("TestAddr = " + testAddr.toString());
			Address found =
				memory.findBytes(currentProgram.getMinAddress(), addressBytes, maskBytes, true,
					monitor);
			if (found != null) {
				ref = found;
				//	println("Found ref at " + found.toString());				
				noRefFound = false;
			}
			else {
				longIndex++;
				// check to see if we are at the top of the range of possible refs
				if (longIndex > (dist - 4)) {// change the four to pointer size when I add 64bit 
					tryPrevAddr = false;
				}

			}
		}
		return ref;
	}

	byte[] turnAddressIntoBytes(Address addr) {
//		 turn addresses into bytes

		byte[] addressBytes = new byte[4]; // only 32-bit for now - change later to add 64 bit
		// This is the correct way to do turn a long into an address
		long addrLong = addr.getOffset();

		int endian = getEndian();

		if (endian == BIG_ENDIAN) {
			// put bytes in forward order
			addressBytes = bytesForward(addrLong);
		}
		else if (endian == LITTLE_ENDIAN) {
			// put bytes in reverse order
			addressBytes = bytesReversed(addrLong);
		}
		else {
			println("Unknown endian - cannot find references.");
			return null;
		}

		return addressBytes;
	}

	byte[] bytesForward(long addr) {
		byte[] bytes = new byte[4]; // only works for 32-bit for now-later add 64
		for (int i = 0; i < 4; i++) {
			bytes[i] = (byte) ((addr >> (24 - (i * 8))) & 0xff);
		}
		return bytes;
	}

	byte[] bytesReversed(long addr) {
		byte[] bytes = new byte[4]; // only works for 32-bit for now-later add 64
		for (int i = 3; i >= 0; i--) {
			bytes[3 - i] = (byte) ((addr >> (24 - (i * 8))) & 0xff);
		}
		return bytes;
	}

	// find references to the possible table 
	// start looking at the top of the array and work back the distance between the pointers in
	// the table
//	Address [] findReferenceToTable(Address topAddress, long dist){	
//						
//		ArrayList<Address> foundAddrs = new ArrayList<Address>();
//		long counter = 0;
//		while((foundAddrs.size() == 0) || (counter == (dist-1))){
//			List<Address> newList = findReferences(topAddress.subtract(dist-counter));
//			for(int i=0;i<newList.size();i++){
//				Address a = (Address)newList.get(i);
//				foundAddrs.add(a);
//			}
//			counter++;
//		}
//		
//		return (Address[]) foundAddrs.toArray();
//	}

//public List<Address> findReferences(Address addr){
//	  FindPossibleReferences fpr = new FindPossibleReferences(currentProgram,getEndian());
//	  return fpr.findReferences(addr);
//}

	public int getEndian() {

		if (currentProgram.getLanguage().isBigEndian()) {
			return 1; // BIG_ENDIAN
		}
		return 0; // LITTLE_ENDIAN
	}

//  info about the pushed parameter that gets applied to the calling functions params and locals and referenced data
	class PossiblePtrs {

		private Address addrOfPtr;
		private Address possiblePtr;
		private long distanceFromLast;

		PossiblePtrs(Address addrOfPtr, Address possiblePtr, long distanceFromLast) {

			this.addrOfPtr = addrOfPtr;
			this.possiblePtr = possiblePtr;
			this.distanceFromLast = distanceFromLast;
		}

		public Address getAddrOfPtr() {
			return addrOfPtr;
		}

		public Address getPossiblePointer() {
			return possiblePtr;
		}

		public long getDistanceFromLast() {
			return distanceFromLast;
		}
	}

	class Table {
		private Address topAddr;
		private long distance;
		private int numPointers;
		Address ref;

		Table(Address topAddr, long distance, int numPointers, Address ref) {
			this.topAddr = topAddr;
			this.distance = distance;
			this.numPointers = numPointers;
			this.ref = ref;
		}

		public Address getTopAddr() {
			return topAddr;
		}

		public long getDistance() {
			return distance;
		}

		public int getNumPointers() {
			return numPointers;
		}

		public Address getRef() {
			return ref;
		}

	}
}
