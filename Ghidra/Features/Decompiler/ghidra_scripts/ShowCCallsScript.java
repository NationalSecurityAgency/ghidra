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
// Given a routine, show all the calls to that routine and their parameters.
//    Place the cursor on a function (can be an external .dll function).
//    Execute the script.
//    The decompiler will be run on everything that calls the function at the cursor
//    All calls to the function will display with their parameters to the function.
//
//   This script assumes good flow, that switch stmts are good.
//
//@category Functions

import java.util.Iterator;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class ShowCCallsScript extends GhidraScript {

    private Address lastAddr = null;

    @Override
    public void run() throws Exception {

        if (currentLocation == null) {
            println("No Location.");
            return;
        }

        Listing listing = currentProgram.getListing();

        Function func = listing.getFunctionContaining(currentAddress);

        if (func == null) {
            println("No Function at address " + currentAddress);
            return;
        }

        DecompInterface decomplib = setUpDecompiler(currentProgram);
        
        try {
        	if (!decomplib.openProgram(currentProgram)) {
        		println("Decompile Error: " + decomplib.getLastMessage());
        		return;
        	}

	        // call decompiler for all refs to current function
	        Symbol sym = this.getSymbolAt(func.getEntryPoint());
	
	        Reference refs[] = sym.getReferences(null);
	
	        for (int i = 0; i < refs.length; i++) {
	            if (monitor.isCancelled()) {
	                break;
	            }
	
	            // get function containing.
	            Address refAddr = refs[i].getFromAddress();
	            Function refFunc = currentProgram.getFunctionManager()
	                    .getFunctionContaining(refAddr);
	
	            if (refFunc == null) {
	                continue;
	            }
	
	            // decompile function
	            // look for call to this function
	            // display call
	            analyzeFunction(decomplib, currentProgram, refFunc, refAddr);
	        }
        }
        finally {
        	decomplib.dispose();
        }

        lastAddr = null;
    }

	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decomplib = new DecompInterface();
        
		DecompileOptions options;
		options = new DecompileOptions(); 
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null,opt,program);    	
		}
        decomplib.setOptions(options);
        
		decomplib.toggleCCode(true);
		decomplib.toggleSyntaxTree(true);
		decomplib.setSimplificationStyle("decompile");
		
		return decomplib;
	}

    /**
     * Analyze a functions references
     */
    public void analyzeFunction(DecompInterface decomplib, Program prog, Function f, Address refAddr) {

        if (f == null) {
            return;
        }

        // don't decompile the function again if it was the same as the last one
        //
        if (!f.getEntryPoint().equals(lastAddr))
            decompileFunction(f, decomplib);
        lastAddr = f.getEntryPoint();

        Instruction instr = prog.getListing().getInstructionAt(refAddr);
        if (instr == null) {
            return;
        }

        println(printCall(f, refAddr));
    }



    HighFunction hfunction = null;

    ClangTokenGroup docroot = null;

    public boolean decompileFunction(Function f, DecompInterface decomplib) {
    	// decomplib.setSimplificationStyle("normalize", null);
        // HighFunction hfunction = decomplib.decompileFunction(f);

        DecompileResults decompRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), monitor);
        //String statusMsg = decomplib.getDecompileMessage();

        hfunction = decompRes.getHighFunction();
        docroot = decompRes.getCCodeMarkup();

        if (hfunction == null)
        	return false;

        return true;
    }

    /**
     * get the pcode ops that refer to an address
     */
    public Iterator<PcodeOpAST> getPcodeOps(Address refAddr) {
        if (hfunction == null) {
            return null;
        }
        Iterator<PcodeOpAST> piter = hfunction.getPcodeOps(refAddr.getPhysicalAddress());
        return piter;
    }

    public String printCall(Function f, Address refAddr) {
        StringBuffer buff = new StringBuffer();

        printCall(refAddr, docroot, buff, false, false);

        return buff.toString();
    }

    private boolean printCall(Address refAddr, ClangNode node, StringBuffer buff, boolean didStart, boolean isCall) {
    	if (node == null) {
    		return false;
    	}
    	
    	Address min = node.getMinAddress();
        Address max = node.getMaxAddress();
        if (min == null)
            return false;

        if (refAddr.getPhysicalAddress().equals(max) && node instanceof ClangStatement) {
        	ClangStatement stmt = (ClangStatement) node;
        	// Don't check for an actual call. The call could be buried more deeply.  As long as the original call reference site
        	// is the max address, then display the results.
        	// So this block assumes that the last address contained in the call will be the
        	// address you are looking for.
        	//    - This could lead to strange behavior if the call reference is placed on some address
        	//    that is not the final call point used by the decompiler.
        	//    - Also if there is a delay slot, then the last address for the call reference point
        	//    might not be the last address for the block of PCode.
        	//if (stmt.getPcodeOp().getOpcode() == PcodeOp.CALL) {
	        	if (!didStart) {
	        		Address nodeAddr = node.getMaxAddress();
	        		// Decompiler only knows base space.
	        		//   If reference came from an overlay space, convert address back
	        	    if (refAddr.getAddressSpace().isOverlaySpace()) {
	        	        nodeAddr = refAddr.getAddressSpace().getOverlayAddress(nodeAddr);
	        	    }
	        		buff.append(" " + nodeAddr + "   : ");
	        	}
	        	
	        	buff.append("   " + toString(stmt));
	        	return true;
        	//}
        }
        for (int j = 0; j < node.numChildren(); j++) {
        	isCall = node instanceof ClangStatement;
            didStart |= printCall(refAddr, node.Child(j), buff, didStart, isCall);
        }
        return didStart;
    }

	public String toString(ClangStatement node) {
	    StringBuffer buffer = new StringBuffer();
		int open=-1;
        for (int j = 0; j < node.numChildren(); j++) {
	        ClangNode subNode = node.Child(j);
	        if (subNode instanceof ClangSyntaxToken) {
	        	ClangSyntaxToken syntaxNode = (ClangSyntaxToken) subNode;
	        	if (syntaxNode.getOpen() != -1) {
	        		if (node.Child(j+2) instanceof ClangTypeToken) {
	        			open = syntaxNode.getOpen();
		        		continue;
	        		}
	        	}
	        	if (syntaxNode.getClose() == open && open != -1) {
	        		open = -1;
	        		continue;
	        	}
	        }
        	if (open != -1) {
        		continue;
        	}
	        buffer.append(subNode.toString());
	    }
	    return buffer.toString();
	}
}

