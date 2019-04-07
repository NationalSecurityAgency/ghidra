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
//Upgrade DEX program(s) that have function prototypes layed down prior to Ghidra 7.1 
//@category    Upgrade

import java.util.Map;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;

/**
 * There was a major rearrangement of registers in the Dalvik.slaspec from 7.0 -> 7.1 which invalidates function prototypes
 * laid down by "Android DEX Header Format" analyzer.  This script repairs the prototypes to match the new register layout
 * If run with a Program already up, the script will make all the changes, letting the user decide if they want to
 * save (or undo) the changes.  If the script is run from an empty code browser, it will search for all Dalvik programs
 * in the current project and automatically upgrade and save the function prototypes.
 *
 */
public class UpgradeDexToGhidra71Script extends GhidraScript {

    @Override
    public void run() throws Exception {
        
        if ( currentProgram != null ) {
            processProgram(currentProgram);
            return;
        }
        
        PluginTool tool = state.getTool();
        Project project = tool.getProject();
        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();
        recurseProjectFolder( rootFolder );
    }
    
    private void recurseProjectFolder( DomainFolder domainFolder ) throws Exception {
        DomainFile[] files = domainFolder.getFiles();
        for ( DomainFile domainFile : files ) {
        	monitor.checkCanceled();
        	try {
        		processDomainFile( domainFile );
        	} catch(Exception ex) {
        		printerr(ex.getMessage());
        	}
        }
        DomainFolder[] folders = domainFolder.getFolders();
        for ( DomainFolder folder : folders ) {
        	monitor.checkCanceled();
            recurseProjectFolder( folder );
        }
    }
    
	private void processDomainFile(DomainFile domainFile ) throws Exception {
		Map<String, String> metadata = domainFile.getMetadata();
		if (metadata == null) {
			return;
		}
		String formatString = metadata.get("Executable Format");
		if (formatString == null) {
			return;
		}
		if (!formatString.equals("Dalvik Executable (DEX)")) {
			return;
		}
		DomainObject domainObject = domainFile.getDomainObject(this, true, true, monitor);
		try {
			Program program = (Program) domainObject;
			processProgram(program);
			saveProgram(program);
		} finally {
			domainObject.release(this);
		}
	}

	private void processProgram(Program program) throws CancelledException {
		println("Updating program: "+program.getName());
		int id = program.startTransaction("Update DEX parameters");
		boolean success = false;
		try {
			for (Function func : program.getFunctionManager().getFunctions(true)) {
				monitor.checkCanceled();
				processFunction(func);
			}
			success = true;
		} finally {
			program.endTransaction(id, success);
		}
	}

	private void processFunction(Function func) {
		monitor.setMessage("Updating: "+func.getName());
		FunctionDefinitionDataType sig = new FunctionDefinitionDataType(func,false);
		sig.setGenericCallingConvention(GenericCallingConvention.stdcall);
		func.setCustomVariableStorage(false);
		ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(func.getEntryPoint(),sig,SourceType.ANALYSIS);
		cmd.applyTo(func.getProgram());
		
		Program program = func.getProgram();
		Language language = program.getLanguage();
		AddressSpace registerSpace = program.getAddressFactory().getRegisterSpace();
		Variable[] localVariables = func.getLocalVariables();
		
		for (Variable var : localVariables) {
			Varnode varnode = var.getFirstStorageVarnode();
			if (!varnode.isRegister()) {
				continue;
			}
			if (varnode.getOffset() >= 0x1000)
			 {
				continue;		// Already converted
			}
			long offset = varnode.getOffset() + 0x1000 - 8;
			int size = varnode.getSize();
			Register localRegister = language.getRegister(registerSpace, offset, size);
			try {
				LocalVariableImpl newlocal = new LocalVariableImpl( var.getName(), 0, var.getDataType(), localRegister, func.getProgram() );
				func.removeVariable(var);
				func.addLocalVariable(newlocal, SourceType.ANALYSIS);
			} catch (InvalidInputException e) {
			} catch (DuplicateNameException e) {
			}
			
		}
	}
}
