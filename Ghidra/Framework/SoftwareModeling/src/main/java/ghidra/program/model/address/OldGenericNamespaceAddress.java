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
package ghidra.program.model.address;


/**
 * <code>OldGenericNamespaceAddress</code> provides a means of instantiating namespace 
 * oriented addresses which were previously used for External, Stack and Register addresses.
 * This class is needed to facilitate an upgrade since this concept is no longer supported by Address.
 */
public class OldGenericNamespaceAddress extends GenericAddress {

	/**
	 * OLD_MIN_NAMESPACE_ID provides the minimum non-global namespace-ID supported by the
	 * old namespace address.
	 */
	public static final long OLD_MIN_NAMESPACE_ID = 1;
	
	/**
	 * OLD_MAX_NAMESPACE_ID provides the maximum non-global namespace-ID supported by the
	 * old namespace address.  This was a function of the old 28-bit encoded address
	 * field used to store this value. 
	 */
	public static final long OLD_MAX_NAMESPACE_ID = 0xfffffff;
	
	long namespaceID;
	
	public OldGenericNamespaceAddress(AddressSpace addrSpace, long offset, long namespaceID) {
		super(addrSpace, offset);
		if (namespaceID < 0 || namespaceID > OLD_MAX_NAMESPACE_ID) {
			throw new IllegalArgumentException("namespaceID too large");
		}
		this.namespaceID = namespaceID;
	}
	
	/**
	 * Returns the namespace ID assigned to this address.
	 * This namespace ID generally corresponds to a Function.
	 */
	public long getNamespaceID() {
		return namespaceID;
	}
	
	/**
	 * Returns global address (i.e., GenericAddress) for this address.
	 */
	public Address getGlobalAddress() {
		return addrSpace.getAddress(offset);
	}
	
	/**
	 * Returns minimum namespace address within the specified address space for upgrade iterators.
	 * A minimum offset of 0x0 is always assumed.  
	 * @param addrSpace address space
	 * @param namespaceID
	 * @return minimum address
	 */
	public static Address getMinAddress(AddressSpace addrSpace, long namespaceID) {
		return new OldGenericNamespaceAddress(addrSpace, 0, namespaceID);
	}
	
	/**
	 * Returns maximum namespace address within the specified address space for upgrade iterators.
	 * For a signed stack space, the negative region is treated as positive for the purpose of 
	 * identifying the maximum address key encoding.
	 * @param addrSpace address space
	 * @param namespaceID
	 * @return maximum address
	 */
	public static Address getMaxAddress(AddressSpace addrSpace, long namespaceID) {
		if (addrSpace.isStackSpace()) {
			return new OldGenericNamespaceAddress(addrSpace, -1, namespaceID);
		}
		return new OldGenericNamespaceAddress(addrSpace, addrSpace.getMaxAddress().getOffset(), namespaceID);
	}
	
	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
    @Override
    public boolean equals(Object o) {
    	if (this == o) {
    		return true;
    	}
    	if (!(o instanceof OldGenericNamespaceAddress)) {
    		return false;
    	}
    	OldGenericNamespaceAddress addr = (OldGenericNamespaceAddress)o;	
    	return addrSpace.equals(addr.getAddressSpace()) &&
    			namespaceID == addr.namespaceID &&
    	       offset == addr.offset;
    }   

}
