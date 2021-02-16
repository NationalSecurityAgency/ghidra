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
package ghidra.app.cmd.data;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

/**
 * A base class to hold duplicate information for commands that create 
 * structures.  This class implements the logic of the 
 * {@link #applyTo(DomainObject)} method so that child implementations need 
 * only to implement the abstract methods.
 * 
 * 
 * @since  Tracker Id 383
 */
public abstract class AbstractCreateStructureCmd implements Command {
    
    private String statusMessage;
    private String structureName;
    private DataType newDataType;
    private Address structureAddress;
    
    /**
     * Initializes the this class to create a structure with the given name 
     * and address when the {@link #applyTo(DomainObject)} is called.
     * 
     * @param name The name of the structure to create.
     * @param address The address of the structure.
     */
    /*package*/ AbstractCreateStructureCmd( String name, Address address ){
        structureAddress = address;
        structureName = name;
    }
    
    /**
     * Applies this command to the given domain object.
     * <p>
     * This method is a Form Template method in that child subclasses do not
     * need to override the method, but only need to implement the methods 
     * that this method calls.
     * 
     * @param domainObject The domain object that is associated with this
     *        command
     * @see   Command#applyTo(DomainObject)
     */
    public boolean applyTo(DomainObject domainObject) {
        try {            
            Program program = (Program) domainObject;
            Structure structure = createStructure( structureAddress, program );            
            setNewDataType( initializeStructureData( program, structure ) );            
        } catch (IllegalArgumentException iae) {
            setStatusMsg( iae.getMessage() );
            return false;
        }
       
        return true;
    }
    
    /**
     * Child classes implement this method in order to create an instance
     * of {@link Structure}. 
     * 
     * @param address The address of the structure.
     * @param program The program of the structure.
     * @return A new StructureInfo object that describes the new structure to
     *         be created.
     * @throws IllegalArgumentException If the data at the given address is
     *         not valid for creating a structure.
     */
    /*package*/ abstract Structure createStructure( Address address,
        Program program )
        throws IllegalArgumentException;
    
    /**
     * Initializes the structure that is represented by the provided
     * <tt>structureInfo</tt> object.  This involves populating the new 
     * structure with data and then returning the data type object that 
     * represents the newly created structure.
     * 
     * @param structureInfo The structure info object that describes the newly
     *        created structure.
     * @return The new data type that represents the created structure.
     */
    /*package*/ abstract DataType initializeStructureData( 
        Program program, Structure structure );
    
    /**
     * Sets the new data type of this command.
     * 
     * @param dataType  The new data type.
     */
    /*package*/ void setNewDataType( DataType dataType ){
        newDataType = dataType;
    }
    
    /**
     * Get the new structure data type which was created.
     * @return new structure.
     */
    public DataType getNewDataType() {
        return newDataType; 
    }
    
    /*package*/ Address getStructureAddress(){
        return structureAddress;
    }
    
    /**
     * Sets the value of the status message for this command
     * 
     * @param message The value of the command.
     */
    /*package*/ void setStatusMsg( String message ){
        statusMessage = message;
    } 
    
    /**
     * @see ghidra.framework.cmd.Command#getStatusMsg()
     */
    public String getStatusMsg(){
        return statusMessage;
    }

    /*package*/ String getStructureName(){
        return structureName;
    }
    
    /**
     * @see ghidra.framework.cmd.Command#getName()
     */
    public String getName(){
        return "Create Structure";
    }
}
