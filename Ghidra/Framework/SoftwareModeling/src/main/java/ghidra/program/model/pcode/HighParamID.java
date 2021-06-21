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
package ghidra.program.model.pcode;

import java.util.ArrayList;
import java.util.List;

import org.xml.sax.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * 
 *
 * High-level abstraction associated with a low level function made up of assembly instructions.
 * Based on information the decompiler has produced after working on a function.
 */
public class HighParamID extends PcodeSyntaxTree {
	public final static String DECOMPILER_TAG_MAP = "decompiler_tags";
	private Function func; // The traditional function object
	private String functionname;
	private Address functionaddress;
	private String modelname; // Name of prototype model
	private Integer protoextrapop;
	private List<ParamMeasure> inputlist = new ArrayList<>();
	private List<ParamMeasure> outputlist = new ArrayList<>();

	/**
	 * @param function  function associated with the higher level function abstraction.
	 * @param language language parser used to disassemble/get info on the language.
	 * @param compilerSpec the compiler spec.
	 * @param dtManager data type manager.
	 */
	public HighParamID(Function function, Language language, CompilerSpec compilerSpec,
			PcodeDataTypeManager dtManager) {
		super(function.getProgram().getAddressFactory(), dtManager);
		func = function;

		modelname = null;
		protoextrapop = PrototypeModel.UNKNOWN_EXTRAPOP;
	}

	/**
	 * @return get the name of the function
	 */
	public String getFunctionName() {
		return functionname;
	}

	/**
	 * @return get the Address of the function
	 */
	public Address getFunctionAddress() {
		return functionaddress;
	}

	/**
	 * @return get the name of the model
	 */
	public String getModelName() {
		return modelname;
	}

	/**
	 * @return get the prototype extrapop information
	 */
	public Integer getProtoExtraPop() {
		return protoextrapop;
	}

	/**
	 * @return get the associated low level function
	 */
	public Function getFunction() {
		return func;
	}

	/**
	 * @return the number of inputs for functionparams
	 */
	public int getNumInputs() {
		return inputlist.size();
	}

	/**
	 * @param i is the specific index to return
	 * @return the specific input for functionparams
	 */
	public ParamMeasure getInput(int i) {
		return inputlist.get(i);
	}

	/**
	 * @return the number of outputs for functionparams
	 */
	public int getNumOutputs() {
		return outputlist.size();
	}

	/**
	 * @param i is the index of the specific output
	 * @return the specific of output for functionparams
	 */
	public ParamMeasure getOutput(int i) {
		return outputlist.get(i);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.pcode.PcodeSyntaxTree#readXML(org.jdom.Element)
	 */
	@Override
	public void readXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement start = parser.start("parammeasures");
		functionname = start.getAttribute("name");
		if (!func.getName().equals(functionname)) {
			throw new PcodeXMLException(
				"Function name mismatch: " + func.getName() + " + " + functionname);
		}
		while (!parser.peek().isEnd()) {
			XmlElement subel = parser.peek();
			if (subel.getName().equals("addr")) {
				subel = parser.start("addr");
				functionaddress = AddressXML.readXML(subel, getAddressFactory());
				parser.end(subel);
				functionaddress =
					func.getEntryPoint().getAddressSpace().getOverlayAddress(functionaddress);
				if (!func.getEntryPoint().equals(functionaddress)) {
					throw new PcodeXMLException("Mismatched address in function tag");
				}
			}
			else if (subel.getName().equals("proto")) {
				subel = parser.start("proto");
				modelname = subel.getAttribute("model");
				String val = subel.getAttribute("extrapop");
				if (val.equals("unknown")) {
					protoextrapop = PrototypeModel.UNKNOWN_EXTRAPOP;
				}
				else {
					protoextrapop = SpecXmlUtils.decodeInt(val);
				}
				parser.end(subel);
			}
			else if (subel.getName().equals("input")) {
				parseParamMeasureXML(parser, inputlist, "input");
			}
			else if (subel.getName().equals("output")) {
				parseParamMeasureXML(parser, outputlist, "output");
			}
			else {
				throw new PcodeXMLException("Unknown tag in parammeasures: " + subel.getName());
			}
		}
		parser.end(start);
	}

	/**
	 * Read in the inputs or outputs list for this function from an XML rep
	 * @param parser is the XML parser
	 * @param pmlist is populated with the resulting list
	 * @param tag is the name of the tag
	 * @throws PcodeXMLException for improperly formed XML
	 */
	private void parseParamMeasureXML(XmlPullParser parser, List<ParamMeasure> pmlist, String tag)
			throws PcodeXMLException {
		XmlElement el = parser.start(tag);
		ParamMeasure pm = new ParamMeasure();
		pm.readXml(parser, this);
		if (!pm.isEmpty()) {
			pmlist.add(pm);
		}
		parser.end(el);
	}

	public static ErrorHandler getErrorHandler(final Object errOriginator,
			final String targetName) {
		return new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				Msg.error(errOriginator, "Error parsing " + targetName, exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				Msg.error(errOriginator, "Fatal error parsing " + targetName, exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(errOriginator, "Warning parsing " + targetName, exception);
			}
		};
	}

	/**
	 * Create and XML SAX parse tree from an input XML string
	 * 
	 * TODO: this probably doesn't belong here.
	 * 
	 * @param xml string to parse
	 * @param handler is the error handler
	 * @return an XML tree element
	 * 
	 * @throws PcodeXMLException for improper XML
	 */
	static public XmlPullParser stringTree(String xml, ErrorHandler handler)
			throws PcodeXMLException {
		try {
			XmlPullParser parser =
				XmlPullParserFactory.create(xml, "Decompiler Result Parser", handler, false);
			return parser;
		}
		catch (Exception e) {
			throw new PcodeXMLException("XML parsing error: " + e.getMessage(), e);
		}
	}

	/**
	 * Update any parameters for this Function from parameters defined in this map.
	 * 
	 * @param storeDataTypes is true if data-types are getting stored
	 * @param srctype function signature source 
	 */
	public void storeReturnToDatabase(boolean storeDataTypes, SourceType srctype) {
		PcodeDataTypeManager dtManage = getDataTypeManager();
		try {
			//TODO: Currently, only storing one output, so looking for the best to report.  When possible, change this to report all
			int best_index = 0;
			if (getNumOutputs() > 1) {
				for (int i = 1; i < getNumOutputs(); i++) {
					if (getOutput(i).getRank() < getOutput(best_index).getRank()) {//TODO: create mirror of ranks on high side (instead of using numbers?)
						best_index = i;
					}
				}
			}
			if (getNumOutputs() != 0) {
				ParamMeasure pm = getOutput(best_index);
				pm.getRank(); //TODO (maybe): this value is not used or stored on the java side at this point
				Varnode vn = pm.getVarnode();
				DataType dataType;
				if (storeDataTypes) {
					dataType = pm.getDataType();
				}
				else {
					dataType = dtManage.findUndefined(vn.getSize());
				}
				//Msg.debug(this, "func: " + func.getName() + " -- type: " + dataType.getName());
				if (!(dataType == null || dataType instanceof VoidDataType)) {
					func.setReturn(dataType, buildStorage(vn), SourceType.ANALYSIS);
				}
			}
		}
		catch (InvalidInputException e) {
			Msg.error(this, e.getMessage());
		}
	}

	/**
	 * Update any parameters for this Function from parameters defined in this map.
	 *   Originally from LocalSymbolMap, but being modified.
	 * 
	 * @param storeDataTypes is true if data-types are being stored
	 * @param srctype function signature source 
	 */
	public void storeParametersToDatabase(boolean storeDataTypes, SourceType srctype) {
		PcodeDataTypeManager dtManage = getDataTypeManager();
		try {
			List<Variable> params = new ArrayList<>();
			for (ParamMeasure pm : inputlist) {
				Varnode vn = pm.getVarnode();
				DataType dataType;
				//Msg.debug(this, "function(" + func.getName() + ")--param size: " + vn.getSize() +
				//	"--type before store: " + pm.getDataType().getName());
				if (storeDataTypes) {
					dataType = pm.getDataType();
				}
				else {
					dataType = dtManage.findUndefined(vn.getSize());
				}
				Variable v = new ParameterImpl(null, dataType, buildStorage(vn), func.getProgram());
				//Msg.debug(this, "function(" + func.getName() + ")--param: " + v.toString() +
				//	" -- type: " + dataType.getName());
				params.add(v);
			}

			func.updateFunction(modelname, null, params,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, srctype);
			if (!paramStorageMatches(func, params)) {
				// try again if dynamic storage assignment does not match decompiler's
				// force into custom storage mode
				func.updateFunction(modelname, null, params, FunctionUpdateType.CUSTOM_STORAGE,
					true, srctype);
			}

		}
		catch (InvalidInputException e) {
			Msg.error(this, e.getMessage());
		}
		catch (DuplicateNameException e) {
			Msg.error(this, e.getMessage());
		}
	}

	private boolean paramStorageMatches(Function function, List<Variable> params) {

		Parameter[] parameters = function.getParameters();
		if (parameters.length != params.size()) {
			return false;
		}
		for (int i = 0; i < parameters.length; i++) {
			if (!parameters[i].getVariableStorage().equals(params.get(i).getVariableStorage())) {
				return false;
			}
		}
		return true;
	}

}
