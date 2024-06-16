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

import org.junit.Assert;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;

public class AbstractProtoModelTest extends AbstractGenericTest {
	protected Language language;
	protected CompilerSpec cspec;
	protected DataTypeManager dtManager;
	protected FunctionSignatureParser parser;
	protected DataTypeParser dataTypeParser;

	protected void buildParsers() {
		parser = new FunctionSignatureParser(dtManager, null);
		dataTypeParser =
			new DataTypeParser(dtManager, dtManager, null, AllowedDataTypes.FIXED_LENGTH);
	}

	protected PrototypePieces parseSignature(PrototypeModel protoModel, String signatureText)
			throws CancelledException, ParseException {
		FunctionDefinitionDataType f = parser.parse(null, signatureText);
		PrototypePieces proto = new PrototypePieces(protoModel, null);
		proto.outtype = f.getReturnType();
		ParameterDefinition[] args = f.getArguments();
		for (int i = 0; i < args.length; ++i) {
			proto.intypes.add(args[i].getDataType());
		}
		return proto;
	}

	protected void parseStructure(String name, String body)
			throws InvalidDataTypeException, CancelledException {
		String[] split = body.split(",");
		StructureDataType struct = new StructureDataType(name, 0, dtManager);
		struct.setPackingEnabled(true);
		for (int i = 0; i < split.length; ++i) {
			DataType element = dataTypeParser.parse(split[i]);
			struct.add(element);
		}
		int txID = dtManager.startTransaction("Add core types");
		try {
			dtManager.addDataType(struct, null);
		}
		finally {
			dtManager.endTransaction(txID, true);
		}

	}

	protected void buildDataTypeManager(String name) {
		dtManager = new StandAloneDataTypeManager(name, cspec.getDataOrganization());
		int txID = dtManager.startTransaction("Add core types");

		try {
			dtManager.addDataType(new VoidDataType(), null);
			dtManager.addDataType(new IntegerDataType(), null);
			dtManager.addDataType(new ShortDataType(), null);
			dtManager.addDataType(new CharDataType(), null);
			dtManager.addDataType(new UnsignedIntegerDataType(), null);
			dtManager.addDataType(new LongDataType(), null);
			dtManager.addDataType(new FloatDataType(), null);
			dtManager.addDataType(new DoubleDataType(), null);
			dtManager.addDataType(new Float16DataType(), null);
			dtManager.addDataType(new Undefined4DataType(), null);
			dtManager.addDataType(new Undefined8DataType(), null);
		}
		finally {
			dtManager.endTransaction(txID, true);
		}

	}

	/**
	 * Obtain a specific CompilerSpec given a language id
	 * @param langId is the 5 long colon separated language id
	 */
	protected void buildArchitecture(String langId) {
		int pos = langId.lastIndexOf(':');
		CompilerSpecID cspecId = new CompilerSpecID(langId.substring(pos + 1));
		LanguageID languageId = new LanguageID(langId.substring(0, pos));
		SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();
		try {
			language = provider.getLanguage(languageId);
		}
		catch (Exception e) {
			String msg = "Language " + languageId + " failed to load: ";
			Msg.error(this, msg, e);
			return;
		}
		cspec = null;
		try {
			cspec = language.getCompilerSpecByID(cspecId);
		}
		catch (Exception e) {
			String msg = "Language " + languageId + " failed to load cspec: " + cspecId;
			Msg.error(this, msg, e);
			return;
		}
		buildDataTypeManager("base");
		buildParsers();
	}

	private ArrayList<Varnode> parseStore(String name) {
		ArrayList<Varnode> res = new ArrayList<>();
		if (name.equals("void")) {
			res.add(null);
			return res;
		}
		if (name.startsWith("stack")) {
			int pos = name.indexOf(':');
			int size = 1;
			if (pos != -1) {
				String sizeString = name.substring(pos + 1);
				size = Integer.parseInt(sizeString);
			}
			else {
				pos = name.length();
			}
			String offsetString = name.substring(5, pos);
			long offset = Long.parseLong(offsetString, 16);
			AddressSpace spc = cspec.getAddressSpace("stack");
			Varnode vn = new Varnode(spc.getAddress(offset), size);
			res.add(vn);
			return res;
		}
		else if (name.startsWith("join")) {
			parseJoin(name, res);
			return res;
		}
		String regname;
		int pos = name.indexOf(':');
		int sz = 0;
		if (pos != -1) {
			String sizeString = name.substring(pos + 1);
			sz = Integer.parseInt(sizeString);
			regname = name.substring(0, pos);
		}
		else {
			regname = name;
		}
		Register register = language.getRegister(regname);
		Address addr = register.getAddress();
		if (sz != 0) {
			if (language.isBigEndian()) {
				addr = addr.add(register.getBitLength() / 8 - sz);
			}
		}
		else {
			sz = register.getBitLength() / 8;
		}
		Varnode vn = new Varnode(addr, sz);
		res.add(vn);
		return res;
	}

	private void parseJoin(String join, ArrayList<Varnode> res) {
		join = join.substring(5);
		String[] split = join.split(" ");
		for (String piece : split) {
			ArrayList<Varnode> onePiece = parseStore(piece);
			res.add(onePiece.get(0));
		}
	}

	protected void parseStores(ArrayList<ArrayList<Varnode>> res, String names) {
		String[] split = names.split(",");
		for (String el : split) {
			ArrayList<Varnode> vnList = parseStore(el);
			res.add(vnList);
		}
	}

	private boolean compareVarnodes(Varnode vn1, Varnode vn2) {
		if (!vn1.getAddress().equals(vn2.getAddress())) {
			return false;
		}
		return (vn1.getSize() == vn2.getSize());
	}

	protected boolean comparePiece(ArrayList<Varnode> vData, ParameterPieces piece)

	{
		if (vData.size() == 1 && vData.get(0) == null) {
			if (piece.address == null) {
				return true;
			}
			return false;
		}
		if (piece.joinPieces != null) {
			if (vData.size() != piece.joinPieces.length) {
				return false;
			}
			for (int i = 0; i < vData.size(); ++i) {
				if (!compareVarnodes(vData.get(i), piece.joinPieces[i])) {
					return false;
				}
			}
			return true;
		}
		if (vData.size() != 1) {
			return false;
		}
		Varnode vn = vData.get(0);
		if (!vn.getAddress().equals(piece.address)) {
			return false;
		}
		return (vn.getSize() == piece.type.getLength());
	}

	protected void test(PrototypeModel model, String signature, String stores)
			throws CancelledException, ParseException {
		PrototypePieces pieces = parseSignature(model, signature);
		ArrayList<ParameterPieces> res = new ArrayList<>();
		model.assignParameterStorage(pieces, dtManager, res, true);
		ArrayList<ArrayList<Varnode>> storeData = new ArrayList<>();
		parseStores(storeData, stores);
		Assert.assertEquals(storeData.size(), res.size());
		for (int i = 0; i < res.size(); ++i) {
			boolean compare = comparePiece(storeData.get(i), res.get(i));
			String message = null;
			if (!compare) {
				StringBuilder buffer = new StringBuilder();
				buffer.append(language.getLanguageID()).append(':');
				buffer.append(cspec.getCompilerSpecID());
				buffer.append(' ').append(model.getName()).append(' ');
				if (i == 0) {
					buffer.append("Output does not match for ");
				}
				else {
					buffer.append("Parameter ").append(i - 1).append(" does not match for: ");
				}
				buffer.append(signature);
				message = buffer.toString();
			}
			Assert.assertTrue(message, compare);
		}
	}

}
