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
package ghidra.program.model.pcode;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;

/**
 * 
 *
 * Interface for classes that build PcodeOps and Varnodes
 */
public interface PcodeFactory {

	/**
	 * @return Address factory
	 */
	public AddressFactory getAddressFactory();

	/**
	 * @return pcode data type manager used to convert strings to Ghidra data types
	 */
	public PcodeDataTypeManager getDataTypeManager();

	/**
	 * Create a new Varnode with the given size and location
	 * 
	 * @param sz size of the Varnode
	 * @param addr location of the Varnode
	 * 
	 * @return a new varnode
	 */
	public Varnode newVarnode(int sz, Address addr);

	/**
	 * Create a new Varnode with the given size and location.
	 * Associate the Varnode with a specific reference id so that it can be retrieved,
	 * using just the id, via getRef();
	 * @param sz size of the Varnode
	 * @param addr location of the Varnode 
	 * @param refId is the specific reference id
	 * @return the new Varnode
	 */
	public Varnode newVarnode(int sz, Address addr, int refId);

	/**
	 * Create a storage object representing a value split across multiple physical locations.
	 * The sequence of physical locations are passed in as an array of Varnodes and the storage
	 * object is returned.  The storage is also assigned an Address in the join address space,
	 * which can be retrieved by calling the getJoinAddress() method.  The join Address can
	 * be used to create a Varnode that represents the logical whole created by concatenating
	 * the Varnode pieces.
	 * @param pieces is the array of Varnode pieces to join
	 * @return the VariableStorage representing the whole
	 * @throws InvalidInputException if a valid storage object cannot be created
	 */
	public VariableStorage getJoinStorage(Varnode[] pieces) throws InvalidInputException;

	/**
	 * Get the address (in the "join" space) corresponding to the given multi-piece storage.
	 * The storage must have been previously registered by a previous call to getJoinStorage().
	 * If the storage is not multi-piece or was not registered, null is returned.
	 * @param storage is the multi-piece storage
	 * @return the corresponding "join" address
	 */
	public Address getJoinAddress(VariableStorage storage);

	/**
	 * Build a storage object for a particular Varnode
	 * @param vn is the Varnode
	 * @return the storage object
	 * @throws InvalidInputException if valid storage cannot be created
	 */
	public VariableStorage buildStorage(Varnode vn) throws InvalidInputException;

	/**
	 * Return a Varnode given its reference id, or null if the id is not registered.
	 * The id must have previously been registered via newVarnode().
	 * @param refid is the reference id
	 * @return the matching Varnode or null
	 */
	public Varnode getRef(int refid);

	/**
	 * Get a PcodeOp given a reference id.  The reference id corresponds to the op's
	 * SequenceNumber.getTime() field.  Return null if no op matching the id has been registered
	 * via newOp().
	 * @param refid is the reference id
	 * @return the matching PcodeOp or null
	 */
	public PcodeOp getOpRef(int refid);

	/**
	 * Get the high symbol matching the given id that has been registered with this object
	 * @param symbolId is the given id
	 * @return the matching HighSymbol or null
	 */
	public HighSymbol getSymbol(long symbolId);

	/**
	 * Mark (or unmark) the given Varnode as an input (to its function)
	 * @param vn is the given Varnode
	 * @param val is true if the Varnode should be marked
	 * @return the altered Varnode, which may not be the same object passed in
	 */
	public Varnode setInput(Varnode vn, boolean val);

	/**
	 * Mark (or unmark) the given Varnode with the "address tied" property
	 * @param vn is the given Varnode
	 * @param val is true if the Varnode should be marked
	 */
	public void setAddrTied(Varnode vn, boolean val);

	/**
	 * Mark (or unmark) the given Varnode with the "persistent" property
	 * @param vn is the given Varnode
	 * @param val is true if the Varnode should be marked
	 */
	public void setPersistent(Varnode vn, boolean val);

	/**
	 * Mark (or unmark) the given Varnode with the "unaffected" property
	 * @param vn is the given Varnode
	 * @param val is true if the Varnode should be marked
	 */
	public void setUnaffected(Varnode vn, boolean val);

	/**
	 * Associate a specific merge group with the given Varnode
	 * @param vn is the given Varnode
	 * @param val is the merge group
	 */
	public void setMergeGroup(Varnode vn, short val);

	/**
	 * Attach a data-type to the given Varnode
	 * @param vn is the given Varnode
	 * @param type is the data-type
	 */
	public void setDataType(Varnode vn, DataType type);

	/**
	 * Create a new PcodeOp given its opcode, sequence number, and input and output Varnodes
	 * @param sq is the sequence number
	 * @param opc is the opcode
	 * @param inputs is the array of input Varnodes, which may be empty
	 * @param output is the output Varnode, which may be null
	 * @return the new PcodeOp
	 */
	public PcodeOp newOp(SequenceNumber sq, int opc, ArrayList<Varnode> inputs, Varnode output);

}
