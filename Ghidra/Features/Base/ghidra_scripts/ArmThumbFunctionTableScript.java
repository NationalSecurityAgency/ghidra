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
//Makes functions out of a run of selected ARM or Thumb function pointers 
//@category ARM 


import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

import java.math.BigInteger;

public class ArmThumbFunctionTableScript extends GhidraScript 
{ 
   @Override
public void 
   run() throws Exception 
   { 
      Register tmode = currentProgram.getProgramContext().getRegister("TMode"); 
      Listing lst = currentProgram.getListing(); 
      if (currentSelection != null) 
      { 
         AddressIterator addrIter = currentSelection.getAddresses(true); 
         
         while (addrIter.hasNext()) 
         { 
            Address currAddr = addrIter.next(); 
            // Only look at dword-aligned boundaries for function pointers 
            if ((currAddr.getOffset() & 3) != 0) 
            { 
               continue; 
            } 
            // Skip over entries with value 0 (null pointers) 
            long dstOffset = getInt(currAddr); 
            if (dstOffset == 0) 
            { 
               continue; 
            } 
            // Clear any defined data before applying our new type 
            if (!lst.isUndefined(currAddr,currAddr.add(3))) 
            { 
               clearListing(currAddr, currAddr.add(3)); 
            } 
            // Apply a pointer data type 
            createData(currAddr, new Pointer32DataType()); 
            // Now check out what we're pointing to 
            Reference ref = getReferencesFrom(currAddr)[0]; 
            Address refAddr = ref.getToAddress(); 
            if (!currentProgram.getMemory().contains(refAddr)) 
            { 
               continue; 
            } 
            // Decide whether this is a pointer to an ARM or Thumb function 
            BigInteger tmodeValue; 
            if ((dstOffset & 1) == 1) 
            { 
               refAddr = refAddr.subtract(1); 
               tmodeValue = BigInteger.ONE; 
            } 
            else 
            { 
               // ARM function pointers should always be dword-aligned 
               if ((dstOffset & 3) != 0) 
               { 
                  println("Warning: Invalid function pointer to " + refAddr); 
                  continue; 
               } 
               tmodeValue = BigInteger.ZERO; 
            } 
             
            // Check current TMode at referenced address 
            BigInteger currVal = 
               currentProgram.getProgramContext().getValue(tmode, refAddr, false); 
            if (currVal == null) 
            { 
               currVal = BigInteger.ZERO; 
            } 
            // If the TMode isn't set correctly, fix it here 
            if (currVal.compareTo(tmodeValue) != 0) 
            { 
               currentProgram.getProgramContext().setValue( 
                     tmode, 
                     refAddr, 
                     refAddr, 
                     tmodeValue); 
               // if TMode was wrong but there is code here, 
               // clear the flow so we can disassemble it in the right mode 
               if (!lst.isUndefined(refAddr, refAddr)) 
               { 
                  ClearFlowAndRepairCmd cmd = new ClearFlowAndRepairCmd(refAddr, true, true, false); 
                  runCommand(cmd); 
               } 
            } 
            if (lst.isUndefined(refAddr, refAddr)) 
            { 
               disassemble(refAddr); 
            } 
            if (lst.getFunctionAt(refAddr) == null) 
            { 
               createFunction(refAddr, null); 
            } 
         } 
      }    
   } 
} 

