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
//This script applies labels and comments to the WallaceSrc.exe program for use with GhidraClass exercises 
//@category Training.GhidraClass


import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;

public class MarkupWallaceSrcScript extends GhidraScript {
	

	@Override
	public void run() throws Exception {
		
		if(!currentProgram.getName().contains("WallaceSrc") || (!currentProgram.getExecutableMD5().equals("2527c463a079c81af7b3bc1d26bd3b5d"))) {
			println("This script is only meant to work on the WallaceSrc executable with md5 hash 2527c463a079c81af7b3bc1d26bd3b5d.");
			return;
		}																							
		
		//Create Person structure
		Structure personStruct = new StructureDataType("Person", 0);
		personStruct.add(new IntegerDataType(), "id", "");		
		ArrayDataType adt = new ArrayDataType(new CharDataType(), 32, 1);
		personStruct.add(adt, "name", "");
		personStruct.add(new BooleanDataType(), "likesCheese", "");
		PointerDataType ptrPersonStruct = new PointerDataType(personStruct);
		personStruct.add(ptrPersonStruct, "next", "");
		
		//Create Gadget structure	
		Structure gadgetStruct = new StructureDataType("Gadget", 0);
		PointerDataType charPtr = new PointerDataType(new CharDataType());
		gadgetStruct.add(charPtr,"name","");
		gadgetStruct.add(new IntegerDataType(),"type", "");
		gadgetStruct.add(new BooleanDataType(), "deployed","");
		gadgetStruct.add(ptrPersonStruct, "workingOn","");
		
		//apply data types to function parameters, locals, and returns
		
		//Gadget::Gadget(Gadget * this, undefined4 param_1)
		Function gadgetFunction = getFunctionAt(toAddr(0x00411440));
		Parameter[] parameters = gadgetFunction.getParameters();
		parameters[0] = new ParameterImpl("this", new PointerDataType(gadgetStruct), currentProgram);		
		gadgetFunction.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true, SourceType.USER_DEFINED, parameters);
					
		//deployGadget - return type = Gadget * 
		Function deployGadgetFunction = getFunctionAt(toAddr(0x004118f0));
		deployGadgetFunction.setReturnType(new PointerDataType(gadgetStruct), SourceType.USER_DEFINED);
				
		//initializePeople(Person *) 
		Function initPeopleFunction = getFunctionAt(toAddr(0x004117c0));
		parameters = initPeopleFunction.getParameters();
		parameters[0] = new ParameterImpl("people", new PointerDataType(personStruct), currentProgram);
		initPeopleFunction.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true, SourceType.USER_DEFINED, parameters);		
		
		//use(Gadget *this, Person *person)
		Function useFunction = getFunctionAt(toAddr(0x00411570));
		parameters = useFunction.getParameters();
		parameters[0] = new ParameterImpl("this", new PointerDataType(gadgetStruct), currentProgram);	
		parameters[1] = new ParameterImpl("person", new PointerDataType(personStruct), currentProgram);	
		useFunction.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true, SourceType.USER_DEFINED, parameters);
		
		//addPerson(Person ** list, char * name)
		Function addPersonFunction = getFunctionAt(toAddr(0x00411860));
		parameters = addPersonFunction.getParameters();
		parameters[0] = new ParameterImpl("list", new PointerDataType(new PointerDataType(personStruct)), currentProgram);	
		parameters[1] = new ParameterImpl("name", new PointerDataType(new CharDataType()), currentProgram);	
		addPersonFunction.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true, SourceType.USER_DEFINED, parameters);
		
		//addPeople(Person ** list)
		Function addPeopleFunction = getFunctionAt(toAddr(0x00411700));
		parameters = addPeopleFunction.getParameters();
		parameters[0] = new ParameterImpl("list", new PointerDataType(new PointerDataType(personStruct)), currentProgram);	
		addPeopleFunction.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true, SourceType.USER_DEFINED, parameters);
		
		//print(Gadget * pGadget)
		Function printFunction = getFunctionAt(toAddr(0x004115d0));
		parameters = printFunction.getParameters();
		parameters[0] = new ParameterImpl("this", new PointerDataType(gadgetStruct), currentProgram);		
		printFunction.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true, SourceType.USER_DEFINED, parameters);
		
		// Create labels for some of the functions
		SymbolTable symbolTable = currentProgram.getSymbolTable();

		
		//create the Class "Gadget" to put most function symbols in
		Namespace namespace = null;
		namespace = symbolTable.getNamespace("Gadget", null);
		if(namespace == null) {
			 namespace = symbolTable.createClass(null, "Gadget", SourceType.USER_DEFINED);
		}
				
		//Functions in Gadget class
		createNewLabel(toAddr(0x00411440), "Gadget", namespace, SourceType.USER_DEFINED);
		createNewLabel(toAddr(0x004115d0), "print", namespace, SourceType.USER_DEFINED);		
		createNewLabel(toAddr(0x00411570), "use", namespace, SourceType.USER_DEFINED);	
		
		//Functions not in class
		createNewLabel(toAddr(0x004117c0), "initializePeople", namespace, SourceType.USER_DEFINED);
		createNewLabel(toAddr(0x004118f0), "deployGadget", namespace, SourceType.USER_DEFINED);		
		createNewLabel(toAddr(0x00411700), "addPeople", namespace, SourceType.USER_DEFINED);
		createNewLabel(toAddr(0x00411860), "addPerson", namespace, SourceType.USER_DEFINED);
		createNewLabel(toAddr(0x00418138), "personList", namespace, SourceType.USER_DEFINED);
		createNewLabel(toAddr(0x00411a30), "main", null, SourceType.USER_DEFINED);		
		
		// Add other labels
		Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x004117c0));	
		createNewLabel(toAddr(0x004117e5), "LoopOverPeople", function, SourceType.USER_DEFINED);
		if(getSymbolAt(toAddr(0x00418138)).getSource().equals(SourceType.DEFAULT)){
			createLabel(toAddr(0x00418138),"personList", true);
		}
		
		// Add comments
	    setPlateComment(toAddr(0x00411440), "This is the init method for the Gadget class");
	    setPlateComment(toAddr(0x004115d0), "This method prints the status of a Person -- whether they are deployed or not and who they are deployed on. ");
	    setPlateComment(toAddr(0x00411700), "This function adds all the people to the Person list.");
	    setPlateComment(toAddr(0x004117c0), "This function initializes each person's record with whether or not they like cheese, their id, and a pointer to the next person.");
	    setPlateComment(toAddr(0x00411860), "This function adds a person to the Person list.");
	    setPlateComment(toAddr(0x004118f0), "This function checks to see if the person on the list is Wallace and if so, it deploys the Infrared Garden Gnome.");
	    setEOLComment(toAddr(0x004117e7), "Randomly assign whether each person likes cheese or not.");	
	}
	
	void createNewLabel(Address address, String name, Namespace namespace, SourceType sourceType) {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		if(getSymbolAt(address).getSource().equals(SourceType.DEFAULT)){
			try {
				symbolTable.createLabel(address, name, namespace, sourceType);
			} catch (InvalidInputException e) {
				println("Invalid input to create label.");
			}
		}
	}
}

