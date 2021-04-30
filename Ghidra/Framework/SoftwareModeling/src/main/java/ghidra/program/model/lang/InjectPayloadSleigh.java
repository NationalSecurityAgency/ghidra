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
package ghidra.program.model.lang;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * <code>InjectPayloadSleigh</code> defines an InjectPayload of p-code which is defined via
 * a String passed to the sleigh compiler
 */
public class InjectPayloadSleigh implements InjectPayload {

	private ConstructTpl pcodeTemplate;
	private int paramShift;
	private boolean isfallthru;		// Precomputed fallthru of inject
	private InjectParameter[] inputlist;
	private InjectParameter[] output;
	protected String name;			// Formal name of this inject
	protected int type;				// type of this payload CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc.
	protected String source;			// Source of this payload
	private String parseString;		// String to be parsed for pcode

	/**
	 * Constructor for use where restoreXml is overridden and provides name and type
	 * @param sourceName
	 */
	protected InjectPayloadSleigh(String sourceName) {
		name = null;
		type = -1;
		inputlist = null;
		output = null;
		source = sourceName;
	}

	public InjectPayloadSleigh clone() {
		InjectPayloadSleigh res = new InjectPayloadSleigh(source);
		res.copy(this);
		return res;
	}

	protected void copy(InjectPayloadSleigh op2) {
		inputlist = null;
		output = null;
		paramShift = op2.paramShift;
		isfallthru = op2.isfallthru;
		name = op2.name;
		type = op2.type;
		source = op2.source;
		parseString = op2.parseString;
		if (op2.inputlist != null) {
			inputlist = new InjectParameter[op2.inputlist.length];
			for (int i = 0; i < inputlist.length; ++i) {
				inputlist[i] =
					new InjectParameter(op2.inputlist[i].getName(), op2.inputlist[i].getSize());
				inputlist[i].setIndex(op2.inputlist[i].getIndex());
			}
		}
		if (op2.output != null) {
			output = new InjectParameter[op2.output.length];
			for (int i = 0; i < output.length; ++i) {
				output[i] = new InjectParameter(op2.output[i].getName(), op2.output[i].getSize());
				output[i].setIndex(op2.output[i].getIndex());
			}
		}
	}

	/**
	 * Provide basic form,  restoreXml fills in the rest
	 * @param nm  must provide formal name
	 * @param tp  must provide type
	 * @param sourceName
	 */
	public InjectPayloadSleigh(String nm, int tp, String sourceName) {
		name = nm;
		type = tp;
		inputlist = null;
		output = null;
		source = sourceName;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getType() {
		return type;
	}

	@Override
	public String getSource() {
		return source;
	}
	
	@Override
	public int getParamShift() {
		return paramShift;
	}

	protected void setInputParameters(ArrayList<InjectParameter> in) {
		inputlist = new InjectParameter[in.size()];
		in.toArray(inputlist);
	}

	protected void setOutputParameters(ArrayList<InjectParameter> out) {
		output = new InjectParameter[out.size()];
		out.toArray(output);
	}

	@Override
	public InjectParameter[] getInput() {
		return inputlist;
	}

	@Override
	public InjectParameter[] getOutput() {
		return output;
	}
	
	@Override
	public void inject(InjectContext context,PcodeEmit emit) {
		ParserWalker walker = emit.getWalker();
		try {
			walker.snippetState();
			setupParameters(context, walker);
			emit.build(pcodeTemplate,-1);
		}
		catch (UnknownInstructionException e) { // Should not be happening in a CallFixup
			e.printStackTrace();
			return;
		}
		catch (MemoryAccessException e) { // Should not be happening in a CallFixup
			e.printStackTrace();
			return;
		}
		emit.resolveRelatives();		
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		SleighParserContext protoContext =
			new SleighParserContext(con.baseAddr, con.nextAddr, con.refAddr, con.callAddr);
		ParserWalker walker = new ParserWalker(protoContext);
		PcodeEmitObjects emit = new PcodeEmitObjects(walker);
		inject(con,emit);
		return emit.getPcodeOp();
	}

	@Override
	public boolean isFallThru() {
		return isfallthru;
	}

	private boolean computeFallThru() {
		OpTpl[] opVec = pcodeTemplate.getOpVec();
		if (opVec.length <= 0) {
			return true;
		}
		switch (opVec[opVec.length - 1].getOpcode()) {
			case PcodeOp.BRANCH:
			case PcodeOp.BRANCHIND:
			case PcodeOp.RETURN:
				return false;
		}
		return true;		
	}

	/**
	 *  All input and output parameters must have a unique index.
	 * Order them so that inputs come first, then outputs
	 */
	protected void orderParameters() {
		int id = 0;
		for (InjectParameter element : inputlist) {
			element.setIndex(id);
			id += 1;
		}
		for (InjectParameter element : output) {
			element.setIndex(id);
			id += 1;
		}		
	}

	public void restoreXml(XmlPullParser parser) {
		ArrayList<InjectParameter> inlist = new ArrayList<InjectParameter>();
		ArrayList<InjectParameter> outlist = new ArrayList<InjectParameter>();
		XmlElement el = parser.start();
		String pshiftstr = el.getAttribute("paramshift");
		paramShift = SpecXmlUtils.decodeInt(pshiftstr);
		boolean isDynamic = false;
		String dynstr = el.getAttribute("dynamic");
		if (dynstr != null)
			isDynamic = SpecXmlUtils.decodeBoolean(dynstr);
		XmlElement subel = parser.peek();
		while(subel.isStart()) {
			subel = parser.start();
			if (subel.getName().equals("body")) {
				parseString = parser.end(subel).getText();
				break;
			}
			String paramName = subel.getAttribute("name");
			int size = SpecXmlUtils.decodeInt(subel.getAttribute("size"));
			InjectParameter param = new InjectParameter(paramName, size);
			if (subel.getName().equals("input"))
				inlist.add(param);
			else
				outlist.add(param);
			parser.end(subel);
			subel = parser.peek();
		}
		parser.end(el);
		if (parseString != null) {
			parseString = parseString.trim();
			if (parseString.length()==0)
				parseString = null;
		}
		if (parseString == null && (!isDynamic))
			throw new SleighException("Missing pcode <body> in injection: "+source);

		setInputParameters(inlist);
		setOutputParameters(outlist);
		orderParameters();
	}
	
	String releaseParseString() {
		String res = parseString;
		parseString = null;			// Don't hold on to a reference
		return res;
	}
	
	//changed to public for PcodeInjectLibraryJava
	public void setTemplate(ConstructTpl ctl) {
		pcodeTemplate = ctl;
		isfallthru = computeFallThru();
	}

	/**
	 * Verify that the storage locations passed -con- match the restrictions for this payload
	 * @param con is InjectContext containing parameter storage locations
	 */
	private void checkParameterRestrictions(InjectContext con,Address addr) {
		int insize = (con.inputlist == null) ? 0 : con.inputlist.size();
		if (inputlist.length != insize)
			throw new SleighException("Input parameters do not match injection specification: "+source);
		for(int i=0;i<inputlist.length;++i) {
			int sz = inputlist[i].getSize();
			if (sz != 0 && sz != con.inputlist.get(i).getSize())
				throw new SleighException("Input parameter size does not match injection specification: "+source);
		}
		int outsize = (con.output == null) ? 0 : con.output.size();
		if (output.length != outsize)
			throw new SleighException("Output does not match injection specification: "+source);
		for(int i=0;i<output.length;++i) {
			int sz = output[i].getSize();
			if (sz != 0 && sz != con.output.get(i).getSize())
				throw new SleighException("Output size does not match injection specification: "+source);
		}
	}
	
	/**
	 * Set-up operands in the parser state so that they pick up storage locations from InjectContext
	 * @param con is the InjectContext containing storage locations
	 * @param walker is the sleigh parser state object
	 * @throws UnknownInstructionException 
	 */
	private void setupParameters(InjectContext con,ParserWalker walker) throws UnknownInstructionException {
		checkParameterRestrictions(con,walker.getAddr());
		for(int i=0;i<inputlist.length;++i) {
			walker.allocateOperand();
			Varnode vn = con.inputlist.get(i);
			FixedHandle hand = walker.getParentHandle();
			hand.space = vn.getAddress().getAddressSpace();
			hand.offset_offset = vn.getOffset();
			hand.size = vn.getSize();
			hand.offset_space = null;
			walker.popOperand();
		}
		for(int i=0;i<output.length;++i) {
			walker.allocateOperand();
			Varnode vn = con.output.get(i);
			FixedHandle hand = walker.getParentHandle();
			hand.space = vn.getAddress().getAddressSpace();
			hand.offset_offset = vn.getOffset();
			hand.size = vn.getSize();
			hand.offset_space = null;
			walker.popOperand();			
		}
	}
}
