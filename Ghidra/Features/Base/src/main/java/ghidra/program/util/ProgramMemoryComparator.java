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
package ghidra.program.util;

import java.util.Arrays;
import java.util.List;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;

/**
 * <CODE>ProgramMemoryComparator</CODE> is a class for comparing two programs and
 * determining the address differences between them.
 */

public class ProgramMemoryComparator {

    /** The first program for the diff. */
    private Program program1;
    
    /** The second program for the diff. */
    private Program program2;
    
    /** Addresses of initialized memory in both programs one and two. 
     *  Addresses in this address set are derived from program1.
     */
    private AddressSet initInBoth;
    
    /** Addresses with same memory type in both programs one and two.
     *  Addresses in this address set are derived from program1.
     */
    private AddressSet sameTypeInBoth;
    
    /** Addresses in both programs one and two.
     *  Addresses in this address set are derived from program1.
     */
    private AddressSet inBoth;
    
    /** Addresses only in program one.
     *  Addresses in this address set are derived from program1.
     */
    private AddressSet onlyInOne;
    
    /** Addresses only in program two.
     *  Addresses in this address set are derived from program2.
     */
    private AddressSet onlyInTwo;

	/** Addresses only in program2 that are compatible with program1.
	 *  Addresses in this address set are derived from program1.
	 */
	private AddressSet compatibleOnlyInTwo;

    /**
     * <CODE>ProgramMemoryComparator</CODE> is used to determine the memory
     * address differences between two programs.
     *
     * @param program1 the first program
     * @param program2 the second program
     * @throws ProgramConflictException if the two programs can't be compared.
     */
    public ProgramMemoryComparator(Program program1, Program program2)
    throws ProgramConflictException {
        this.program1 = program1;
        this.program2 = program2;
        if (program1 == null || program2 == null) {
            throw new IllegalArgumentException("program cannot be null.");
        }
        // Check each program to see if the memory blocks have the same address types.
		if (!similarPrograms(program1, program2)) {
			throw new ProgramConflictException("Address spaces conflict between "
				+ program1.getName() 
				+ " and "
				+ program2.getName() + ".\n");
		}
        
        determineAddressDiffs();
    }

    /**
     * Check each program to see if the memory blocks have the same address types.
     *
     * @param program1 the first program
     * @param program2 the second program
     *
     * @throws ProgramConflictException if the address types for the two programs
     * do not match.
     */
    public static void compareAddressTypes(Program program1, Program program2)
            throws ProgramConflictException {
        // Do the programs have the same types of addresses?
        AddressFactory af1 = program1.getAddressFactory();
        AddressFactory af2 = program2.getAddressFactory();
        if (!af1.equals(af2)){
            throw new ProgramConflictException("Address types conflict between "
                + program1.getName() 
                + " and "
                + program2.getName() + ".\n");
        }
    }
    
    /**
     * Return whether or not the two specified programs are alike 
     * (their language name or address spaces are the same).
     * @param p1 the first program
     * @param p2 the second program
     * @return true if the programs are alike (their language name or address spaces are the same).
     */
	public static boolean similarPrograms(Program p1, Program p2) {
		if (p1 == null || p2 == null) {
			return false;
		}
		if (p1.getLanguageID().equals(p2.getLanguageID())) {
			return true;
		}
		AddressSpace[] spaces1 = p1.getLanguage().getAddressFactory().getAddressSpaces();
		AddressSpace[] spaces2 = p2.getLanguage().getAddressFactory().getAddressSpaces();
		if (spaces1.length != spaces2.length) {
			return false;
		}
		Arrays.sort(spaces1);
		Arrays.sort(spaces2);
		for (int i=0; i<spaces1.length; i++) {
			if (!spaces1[i].equals(spaces2[i])) {
				return false;
			}
		}
		return true;
	}
    
    private void determineAddressDiffs() {
    	// include live blocks as initialized
        AddressSetView initAddrSet1 = ProgramMemoryUtil.getAddressSet(program1, true);
        AddressSetView uninitAddrSet1 = ProgramMemoryUtil.getAddressSet(program1, false);
		
        AddressSetView initAddrSet2 = ProgramMemoryUtil.getAddressSet(program2, true);
        AddressSetView uninitAddrSet2 = ProgramMemoryUtil.getAddressSet(program2, false);
        AddressSet initSet2CompatibleWith1 = DiffUtility.getCompatibleAddressSet(initAddrSet2, program1);
        AddressSet uninitSet2CompatibleWith1 = DiffUtility.getCompatibleAddressSet(uninitAddrSet2, program1);

		// Address Ranges for uninitialized memory in both one and two.
		AddressSetView uninitInBothCompatibleWith1 =
			uninitAddrSet1.intersect(uninitSet2CompatibleWith1);

        // Address Ranges for initialized memory in both one and two.
        initInBoth = initAddrSet1.intersect(initSet2CompatibleWith1);
        
        // Address Ranges for initialized memory in both one and two.
        sameTypeInBoth = new AddressSet(initInBoth);
        sameTypeInBoth.add(uninitInBothCompatibleWith1);
        
        AddressSetView addrSet1 = ProgramMemoryUtil.getAddressSet(program1);
        AddressSetView addrSet2 = ProgramMemoryUtil.getAddressSet(program2);
        // Address Ranges in both one and two.
        AddressSet addrSet2CompatibleWith1 = DiffUtility.getCompatibleAddressSet(addrSet2, program1);
        inBoth = addrSet1.intersect(addrSet2CompatibleWith1);
        
        // Address Ranges only in one.
        onlyInOne = addrSet1.xor(inBoth);
        
        // Address Ranges only in two.
        AddressSet inBothCompatibleWith2 = DiffUtility.getCompatibleAddressSet(inBoth, program2);
        onlyInTwo = addrSet2.xor(inBothCompatibleWith2);

		compatibleOnlyInTwo = DiffUtility.getCompatibleAddressSet(onlyInTwo, program1);
    }

    /** Gets the first program being compared by the ProgramMemoryComparator.
     * @return program1.
     */
    public Program getProgramOne() {
        return program1;
    }

    /** Gets the second program being compared by the ProgramMemoryComparator.
     * @return program2.
     */
    public Program getProgramTwo() {
        return program2;
    }

    /** Returns the addresses from combining the address sets in program1 and program2.
     *  Addresses in the returned address set are derived from program1.
     * @return the addresses for both program1 and program2.
     */
	public static AddressSet getCombinedAddresses(Program program1, Program program2) {

		AddressSetView addrSet1 = ProgramMemoryUtil.getAddressSet(program1);
		AddressSetView addrSet2 = ProgramMemoryUtil.getAddressSet(program2);
		AddressSet addrSet2CompatibleWith1 =
			DiffUtility.getCompatibleAddressSet(addrSet2, program1);
		return addrSet1.union(addrSet2CompatibleWith1);
    }

    /** Returns an iterator for the address ranges in the set containing the combined addresses
     *  in program1 and program2.
     *  Address ranges from this iterator are derived using program1.
     * @return the addresses for both program1 and program2.
     */
    public AddressRangeIterator getAddressRanges() {
    	return getCombinedAddresses(program1, program2).getAddressRanges();
    }

    /** Returns the addresses in common between program1 and program2.
     *  The returned address set is derived using program1.
     * @return the addresses in common between program1 and program2.
     */
    public AddressSet getAddressesInCommon() {
        return new AddressSet(inBoth);
    }

    /** Returns the addresses of initialized memory in common between 
     * program1 and program2. This includes bit memory and live memory.
     * The returned address set is derived using program1.
     * @return the addresses in common between program1 and program2.
     */
    public AddressSet getInitializedAddressesInCommon() {
        return new AddressSet(initInBoth);
    }

    /** Returns the addresses with the same memory types in common between 
     * program1 and program2.
     * The returned address set is derived using program1.
     * @return the addresses in common between program1 and program2.
     */
    public AddressSet getSameMemTypeAddressesInCommon() {
        return new AddressSet(sameTypeInBoth);
    }

    /** Returns the addresses that are in program1, but not in program2
     *  The returned address set is derived using program1.
     * @return the addresses that are in program1, but not in program2.
     */
    public AddressSet getAddressesOnlyInOne() {
        return new AddressSet(onlyInOne);
    }

    /** Returns the addresses that are in program2, but not in program1
     *  The returned address set is derived using program2.
     * @return the addresses that are in program2, but not in program1.
     */
    public AddressSet getAddressesOnlyInTwo() {
        return new AddressSet(onlyInTwo);
    }
    
	/** Returns the set of addresses that are in program2, but not in program1
	 * and that are compatible with program1.
	 *  The returned address set is derived using program1.
	 * @return the addresses that are in program2, but not in program1.
	 */
	public AddressSet getCompatibleAddressesOnlyInTwo() {
		return new AddressSet(compatibleOnlyInTwo);
	}

    /**
     * Return whether or not the memory addresses for the two Programs are different.
     */
    public boolean hasMemoryDifferences() {
        return !(onlyInOne.isEmpty() && onlyInTwo.isEmpty());
    }
    
	/**
	 * Returns true if the register names are the same in both programs.
     * @param program1 the first program
     * @param program2 the second program
     * @return true if the register names are the same
	 */
	static public boolean sameProgramContextRegisterNames(Program program1, Program program2) {
		ProgramContext pc1 = program1.getProgramContext();
		ProgramContext pc2 = program2.getProgramContext();
		List<String> names1 = pc1.getRegisterNames();
		List<String> names2 = pc2.getRegisterNames();
		return names1.equals(names2);
	}
	
}
