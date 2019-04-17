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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;

public class CommonTestData {

    public static CycleGroup byteCycleGroup = new CycleGroup(
                    "Cycle: byte,word,dword,qword", 
                    new DataType[] {new ByteDataType(),
                                    new WordDataType(),
                                    new DWordDataType(),
                                    new QWordDataType()}, 
                    KeyStroke.getKeyStroke(KeyEvent.VK_B, 0));
    public static CycleGroup floatCycleGroup = new CycleGroup(
                    "Cycle: float,double", 
                    new DataType[] {new FloatDataType(),
                                    new DoubleDataType()}, 
                    KeyStroke.getKeyStroke(KeyEvent.VK_F, 0));
    public static CycleGroup asciiCycleGroup = new CycleGroup(
                    "Cycle: char, string, unicode", 
                    new DataType[] {new CharDataType(),
                                    new StringDataType(),
                                    new UnicodeDataType()}, 
                    KeyStroke.getKeyStroke(KeyEvent.VK_QUOTE, 0));
    
    public static StandAloneDataTypeManager dataTypeManager;
    public static Category rootCat;
    public static Category category;
    public static Category aaCategory;
    public static Category bbCategory;
	public static Structure emptyStructure;
	public static Union emptyUnion = new UnionDataType("emptyUnion");
	public static Structure simpleStructure;
	public static Union simpleUnion;
	public static Structure complexStructure;
	public static Structure refStructure;
	public static Union complexUnion;
	public static Union refUnion;
	public static TypeDef simpleStructureTypedef;
	public static DataType arrayDt; 
	public static int transactionID;
	
	public static void cleanUp() {
		dataTypeManager.endTransaction(transactionID, true);
		dataTypeManager.close();
	}
    public static void initialize() {
        try {
			emptyStructure = new StructureDataType("emptyStructure", 0);
			emptyUnion = new UnionDataType("emptyUnion");
			simpleStructure = new StructureDataType("simpleStructure", 0);
			simpleUnion = new UnionDataType("simpleUnion");
			complexStructure = new StructureDataType("complexStructure", 1);
			refStructure = new StructureDataType("refStructure", 0);
			complexUnion = new UnionDataType("complexUnion");
			refUnion = new UnionDataType("refUnion");
			simpleStructureTypedef = new TypedefDataType("simpleStructureTypedef", simpleStructure);
			arrayDt = new ArrayDataType(new Pointer32DataType(new Pointer32DataType(simpleStructureTypedef)),3,4); 
			dataTypeManager = new StandAloneDataTypeManager("test");
			transactionID = dataTypeManager.startTransaction("");						
			rootCat = dataTypeManager.getRootCategory();
            category = rootCat.createCategory("testCat");
            aaCategory = rootCat.createCategory("aa");
            bbCategory = aaCategory.createCategory("bb");
        } catch (InvalidNameException e) {
            e.printStackTrace();
        }

        emptyStructure = (Structure)rootCat.addDataType(emptyStructure, null);
        emptyUnion = (Union)rootCat.addDataType(emptyUnion, null);

        simpleStructure.add(DataType.DEFAULT);      // component 0
        simpleStructure.add(new ByteDataType());    // component 1
        simpleStructure.add(new WordDataType());    // component 2
        simpleStructure.add(new DWordDataType());   // component 3
        simpleStructure.add(new QWordDataType());   // component 4
        simpleStructure.add(new FloatDataType());   // component 5
        simpleStructure.add(new DoubleDataType());  // component 6
        simpleStructure.add(new CharDataType());   // component 7
        simpleStructure.setDescription("My simple structure.");
        simpleStructure = (Structure)bbCategory.addDataType(simpleStructure, null);

        simpleUnion.add(new ByteDataType());
        simpleUnion.add(new WordDataType());
        simpleUnion.add(new DWordDataType());
        simpleUnion.add(new QWordDataType());
        simpleUnion.add(new FloatDataType());
        simpleUnion.add(new DoubleDataType());
        simpleUnion.add(new CharDataType());
        simpleUnion.setDescription("My simple union.");
        simpleUnion = (Union)bbCategory.addDataType(simpleUnion, null);

        complexStructure = (Structure)category.addDataType(complexStructure, null);

        refStructure.add(new Pointer32DataType(complexStructure), 4);
        refStructure = (Structure)category.addDataType(refStructure, null);

        // Note: complexStructure already has a single Undefined byte.
        complexStructure.add(new ByteDataType());
        complexStructure.add(new WordDataType());
        complexStructure.add(new Pointer32DataType(DataType.DEFAULT),4); // Pointer
        complexStructure.add(simpleUnion);
        complexStructure.add(new Pointer16DataType(new Pointer32DataType()),2); // Pointer to structure
        complexStructure.add(new Pointer32DataType(simpleStructure),4); // Pointer to structure
        complexStructure.add(new Pointer16DataType(new StringDataType()),2); // Pointer to union
        complexStructure.add(new Pointer64DataType(new Pointer32DataType(new ByteDataType())),8); // Pointer to union
        complexStructure.add(new Pointer8DataType(simpleUnion),1); // Pointer to union
        complexStructure.add(new Pointer32DataType(complexStructure),4); // Pointer to this structure
        complexStructure.add(DataType.DEFAULT);
        complexStructure.add(DataType.DEFAULT);
        complexStructure.add(DataType.DEFAULT);
        complexStructure.add(new ArrayDataType(new ByteDataType(), 7, 1)); // Basic Array
        complexStructure.add(new ArrayDataType(new StringDataType(), 5, 9)); // Variable array
        complexStructure.add(new ArrayDataType(simpleStructure, 3, simpleStructure.getLength())); // structure array
        complexStructure.add(new ArrayDataType(new Pointer64DataType(simpleStructure), 7, 8)); // structure pointer array
        complexStructure.add(new TypedefDataType("FloatTypedef", new FloatDataType())); // typedef of a basic data type.
        TypeDef tempSimpleStructureTypedef = new TypedefDataType("simpleStructureTypedef", simpleStructure);
        complexStructure.add(tempSimpleStructureTypedef); // typedef of a variable data type.
        DataType tempArrayDt = new ArrayDataType(new Pointer32DataType(new Pointer32DataType(tempSimpleStructureTypedef)), 3, 4);
        complexStructure.add(new ArrayDataType(tempArrayDt, 2, tempArrayDt.getLength())); // Pointer to a structure containing pointer to this structure.
        complexStructure.add(simpleStructure);
        complexStructure.add(new Pointer32DataType(refStructure), 4); // Pointer to structure containing pointer to this structure.

        complexStructure.setDescription("A complex structure.");
        complexUnion = (Union)category.addDataType(complexUnion, null);

        refUnion.add(new Pointer32DataType(complexUnion), 4);
        refUnion = (Union)category.addDataType(refUnion, null);

        complexUnion.add(new ByteDataType());
        complexUnion.add(new WordDataType());
        complexUnion.add(new Pointer32DataType(DataType.DEFAULT),4); // Pointer
        complexUnion.add(simpleUnion);
        complexUnion.add(new Pointer16DataType(new Pointer32DataType()),2); // Pointer to structure
        complexUnion.add(new Pointer32DataType(simpleStructure),4); // Pointer to structure
        complexUnion.add(new Pointer16DataType(new StringDataType()),2); // Pointer to union
        complexUnion.add(new Pointer64DataType(new Pointer32DataType(new ByteDataType())), 8); // Pointer to union
        complexUnion.add(new Pointer8DataType(simpleUnion),1); // Pointer to union
        complexUnion.add(new Pointer32DataType(complexStructure),4); // Pointer to this structure
        complexUnion.add(new ArrayDataType(new ByteDataType(), 7, 1)); // Basic Array
        complexUnion.add(new ArrayDataType(new StringDataType(), 5, 9)); // Variable array
        complexUnion.add(new ArrayDataType(simpleStructure, 3, simpleStructure.getLength())); // structure array
        complexUnion.add(new ArrayDataType(new Pointer64DataType(simpleStructure), 7, 8)); // structure pointer array
        complexUnion.add(new TypedefDataType("FloatTypedef", new FloatDataType())); // typedef of a basic data type.
        complexUnion.add(tempSimpleStructureTypedef); // typedef of a variable data type.
        TypeDef simpleUnionTypedef = new TypedefDataType("simpleUnionTypedef", simpleUnion);
        complexUnion.add(simpleUnionTypedef); // typedef of a variable data type.
        complexUnion.add(new ArrayDataType(tempArrayDt, 2, tempArrayDt.getLength())); // Pointer to a structure containing pointer to this structure.
        complexUnion.add(new Pointer32DataType(refStructure),4); // Pointer to structure containing pointer to this structure.
        complexUnion.add(new Pointer32DataType(refUnion),4); // Pointer to union containing pointer to this union.
        complexUnion.add(simpleStructure);
        complexUnion.setDescription("A complex union.");
    }
    
}
