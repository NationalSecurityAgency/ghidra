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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

/**
 * Command to create a structure inside of another structure.
 * 
 */
public class CreateStructureInStructureCmd extends AbstractCreateStructureCmd{
	private int[] fromPath;
	private int[] toPath;
	private Structure structure;
    
    /**
     * Constructs a new command for creating structures inside other structures.
     * @param address the address of the outer-most structure.
     * @param fromPath the componentPath of the first component to be consumed in 
     * the new structure.
     * @param toPath the componentPath of the second component to be consumed in the
     * the new structure.
     */
    public CreateStructureInStructureCmd( Address address, int[] fromPath, int[] toPath ){
        this( StructureFactory.DEFAULT_STRUCTURE_NAME, address, fromPath, toPath );
    }
    
	/**
	 * Constructs a new command for creating structures inside other structures.
     * 
     * @param name The name of the structure.
	 * @param addr the address of the outer-most structure.
	 * @param fromPath the componentPath of the first component to be consumed in 
	 * the new structure.
	 * @param toPath the componentPath of the second component to be consumed in the
	 * the new structure.
	 */
	public CreateStructureInStructureCmd( String name, Address addr, int[] fromPath, int[] toPath){
        super( name, addr );        
		this.fromPath = fromPath;
		this.toPath = toPath;
	}

    public CreateStructureInStructureCmd( Structure newStructure, 
        Address address, int[] fromPath, int[] toPath ){
        this( address, fromPath, toPath );
        structure = newStructure;
    }    
    
    /* 
     * @see AbstractCreateStructureCmd#createStructure(Address, Program)
     */
    /*package*/ @Override
    Structure createStructure( Address address,
        Program program ){
        
        if ( structure == null ){
            structure = StructureFactory.createStructureDataTypeInStrucuture( 
                program, address, fromPath, toPath, getStructureName(), true );
        }
        
        return structure;
    }
    
    /*
     * @see AbstractCreateStructureCmd#initializeStructureData(StructureInfo)
     */
    /*package*/ @Override
    DataType initializeStructureData( Program program, Structure localStructure ){
        
        Data data = program.getListing().getDataContaining( 
            getStructureAddress() );           
        Data comp1 = data.getComponent( fromPath );
        Data comp2 = data.getComponent(toPath);
        int dataLength = (comp2.getParentOffset() + comp2.getLength())
            - comp1.getParentOffset();
        
        DataType parentDataType = comp1.getParent().getBaseDataType();        
        if ( !(parentDataType instanceof Structure) ){
            throw new IllegalArgumentException(
                "Data not in a structure");
        }        
        Structure originalStructure = (Structure) parentDataType;        
        
        // clear and initialize the original structure and then get the new
        // data
        clearStruct(originalStructure, comp1.getParentOffset(), dataLength );
        originalStructure.replace(comp1.getComponentIndex(), 
            localStructure, localStructure.getLength());
        comp1 = data.getComponent( fromPath );
        
        return comp1.getDataType();
    }

    private void clearStruct(Structure struct, int offset, int length) {
        DataTypeComponent[] comps = struct.getDefinedComponents();
        int endOffset = offset+length;
        for(int i=comps.length-1;i>=0;i--) {
            if (comps[i].getOffset() >= offset && comps[i].getOffset() < endOffset) {
                struct.clearComponent(comps[i].getOrdinal());
            }
        }
    }
}
