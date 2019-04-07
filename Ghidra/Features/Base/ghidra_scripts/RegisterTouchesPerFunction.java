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
//This script analyzes how registers are modified in a single
// function or the complete listing and stores the results in the 
// function's plate comment. 
//@category Analysis


import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;

import java.util.*;

public class RegisterTouchesPerFunction extends GhidraScript
{
	private final static String DIVIDER = "*************************************************************\r\n";

    @Override
    public void run() throws Exception
    {
        Listing l = this.currentProgram.getListing();

        if (this.askYesNo("Function Analysis - Register Touches",
                "Analyze complete listing?"))
        {
            FunctionIterator fi = l.getFunctions(true);
            while (fi.hasNext() && !monitor.isCancelled())
            {
                doAnalysis(l, fi.next());
            }
        }
        else
        {
            doAnalysis(l, l.getFunctionContaining(this.currentAddress));
        }
    }

    private void doAnalysis(Listing list, Function func)
    {
    	if (func == null) {
    		println("No function to analyze.");
    		return;
    	}
        HashSet<String> affected, accessed;
        Vector<String> restored;
        Stack<String> pushPops;
        boolean reviewRestored = false;
        Instruction inst;
        InstructionIterator iIter;
        
        monitor.setMessage("Analyzing registers in " + func.getName());

        String comment = list.getComment(CodeUnit.PLATE_COMMENT, func.getBody().getMinAddress());

        if (comment != null && comment.indexOf("TOUCHED REGISTER SUMMARY") > -1)
            return;

        pushPops = new Stack<String>();
        affected = new HashSet<String>();
        accessed = new HashSet<String>();
        restored = new Vector<String>();

        iIter = list.getInstructions(func.getBody(), true);
        
        while (iIter.hasNext() && !monitor.isCancelled())
        {
            inst = iIter.next();

            Object o[] = inst.getResultObjects();
            for (int i = 0; i < o.length; i++)
            {
                if (o[i] instanceof Register)
                {
                    String name = ((Register) o[i]).getName();

                    if (inst.getMnemonicString().equalsIgnoreCase("pop"))
                    {
                        if (!name.equalsIgnoreCase("mult_addr")
                                && !name.equalsIgnoreCase("sp"))
                        {
                            if (pushPops.size() > 0)
                            {
                                restored.add(pushPops.pop() + "->" + name);
                            }
                            else
                            {
                                reviewRestored = true;
                            }
                        }
                    }
                    else
                    {
                        affected.add(name);
                    }
                }
            }
            o = inst.getInputObjects();

            for (int i = 0; i < o.length; i++)
            {
                if (o[i] instanceof Register)
                {
                    String name = ((Register) o[i]).getName();
                    if (inst.getMnemonicString().equalsIgnoreCase("push"))
                    {
                        if (!name.equalsIgnoreCase("mult_addr")
                                && !name.equalsIgnoreCase("sp"))
                        {
                            pushPops.push(name);
                        }
                    }
                    else
                    {
                        accessed.add(name);
                    }
                }
            }
        }

        StringBuffer buffer = new StringBuffer();
        if (comment != null) {
        	buffer.append(comment);
        	buffer.append("\r\n");
        	buffer.append(DIVIDER);
        }
        buffer.append("TOUCHED REGISTER SUMMARY:\r\n");
        buffer.append(DIVIDER);
        buffer.append("Register(s) Affected:\r\n");
        buffer.append(getString(affected, 8));
        buffer.append(DIVIDER);
        buffer.append("Register(s) Accessed:\r\n");
        buffer.append(getString(accessed, 8));
        buffer.append(DIVIDER);
        buffer.append("Register(s) Restored:\r\n");
        buffer.append(getString(restored, 4));

        if(reviewRestored)
        {
        	buffer.append("##Review - due to branches this list may not be accurate\r\n");
            println(func.getName() + " - Review - due to branches this list may not be accurate");
        }
        buffer.append(DIVIDER);

        if (pushPops.size() > 0)
        {

        	buffer.append("Registers Remaining on Stack:\r\n");
        	buffer.append("   "+getString(pushPops, 8));
        }

        list.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, buffer.toString());
    }

    private String getString(Collection<String> c, int itemsPerLine)
    {
        TreeSet<Object> ts = new TreeSet<Object>(c);
        String temp = ts.toString();
        temp = temp.substring(1, temp.length() - 1);
        int i = 0;
        int commaCount = 0;
        while ((i = temp.indexOf(',', i + 1)) >= 0)
        {
            commaCount++;
            if (commaCount % itemsPerLine == 0)
                temp = temp.substring(0, i + 1) + "\r\n"
                        + temp.substring(i + 1).trim();
        }

        return temp + "\r\n";
    }
}
