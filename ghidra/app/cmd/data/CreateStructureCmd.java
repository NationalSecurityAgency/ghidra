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
package ghidra.app.cmd.data;

import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.util.CodeUnitInsertionException;

import java.util.ArrayList;

/**
 * Command to create a structure.
 */
public class CreateStructureCmd extends AbstractCreateStructureCmd{
    private int structureDataLength;
    private Structure structure;
    
    /**
     * Constructs a new command for creating a new structure and applying it to
     * the browser.  This method simply calls 
     * {@link #CreateStructureCmd(String, Address, int)} with 
     * {@link ghidra.program.model.data.StructureFactory#DEFAULT_STRUCTURE_NAME} as the name of the structure.
     * 
     * @param address the address at which to create the new structure.
     * @param length the number of undefined bytes to consume in the new 
     *        structure.
     */
    public CreateStructureCmd( Address address, int length ){
        this( StructureFactory.DEFAULT_STRUCTURE_NAME, address, length );
    }
    
    /**
     * Constructs a new command for creating a new structure and applying it to
     * the browser.
     * @param name The name of the new structure to create.
     * @param address the address at which to create the new structure.
     * @param length the number of undefined bytes to consume in the new 
     *        structure.
     */
    public CreateStructureCmd( String name, Address address, int length ) {
        super( name, address );
        structureDataLength = length;
    }
 
    /**
     * Creates a new structure by using the provided structure and attaching
     * it to the program passed in the {@link #applyTo(DomainObject)} method.
     * 
     * @param newStructure The new structure to attach to the program 
     *        provided in the {@link #applyTo(DomainObject)} method.
     * @param address the address at which to create the new structure.
     */
    public CreateStructureCmd( Structure newStructure, Address address ){
        super( newStructure.getName(), address );
        structure = newStructure;
        structureDataLength = structure.getLength();
    }    
    
    /* 
     * @see AbstractCreateStructureCmd#createStructure(Address, Program)
     */
    @Override
    Structure createStructure( Address address,
        Program program ){        

        if ( structure == null ){            
            structure = 
                StructureFactory.createStructureDataType( program, address, 
                    structureDataLength, getStructureName(), true );
        }
        
        return structure;
    }
    
    /*
     * @see AbstractCreateStructureCmd#initializeStructureData(Program, Structure)
     */
    @Override
    DataType initializeStructureData( Program program, Structure localStructure ){
        
        Listing listing = program.getListing();
        
        Address endAddress;
        try {
            endAddress = getStructureAddress().addNoWrap(structureDataLength - 1);
        } catch (AddressOverflowException e1){
            throw new IllegalArgumentException( 
                "Can't create structure because length exceeds address " +
                "space" + structureDataLength );
        }
        ReferenceManager refMgr = program.getReferenceManager();
        Reference[] refs = findExistingRefs( refMgr, program.getAddressFactory(), getStructureAddress(),
            endAddress );
        listing.clearCodeUnits( getStructureAddress(), endAddress, false );
           
        Data data = null;
        try{
            listing.createData(getStructureAddress(), localStructure, 
                localStructure.getLength());
            refMgr.removeAllReferencesFrom( getStructureAddress(), endAddress );
            addRefs( program, refMgr, refs );
            data = listing.getDataAt( getStructureAddress() );        
        } catch(CodeUnitInsertionException e){
            throw new IllegalArgumentException( e.getMessage() );
        }
        
        return data.getDataType();
    }

    private Reference[] findExistingRefs(ReferenceManager refMgr, AddressFactory af, Address start, Address end) {
        ArrayList<Reference> list = new ArrayList<Reference>();
        AddressIterator it = refMgr.getReferenceSourceIterator(new AddressSet(start, end), true);
        while(it.hasNext()) {
            Address addr = it.next();
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for(int i=0;i<refs.length;i++) {
                list.add(refs[i]);
            }
        }
        Reference[] refList = new Reference[list.size()];
        return list.toArray(refList);      
    }
    
    private void addRefs(Program p, ReferenceManager refMgr, Reference[] refs) {
        for(int i=0;i<refs.length;i++) {
            refMgr.addReference(refs[i]);
        }
    }
}
