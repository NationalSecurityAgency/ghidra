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
package ghidra.app.util.bin.format.golang;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;

import generic.jar.ResourceFile;
import ghidra.app.util.bin.format.dwarf.DWARFUtil;
import ghidra.app.util.bin.format.golang.GoRegisterInfo.RegType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

/**
 * XML config file format:
 * <pre>
 * 	&lt;golang>
 * 		&lt;register_info versions="-1.2,1.3.3-1.4.2,1.8-"> // or "all"
 * 			&lt;int_registers list="RAX,RBX,RCX,RDI,RSI,R8,R9,R10,R11"/>
 * 			&lt;float_registers list="XMM0,XMM1,XMM2,XMM3,XMM4,XMM5,XMM6,XMM7,XMM8,XMM9,XMM10,XMM11,XMM12,XMM13,XMM14"/>
 * 			&lt;stack initialoffset="8" maxalign="8"/>
 * 			&lt;current_goroutine register="R14"/>
 * 			&lt;zero_register register="XMM15" builtin="true|false"/>
 * 			&lt;duffzero dest="RDI" zero_arg="XMM0" zero_type="float|int"/>
 * 			&lt;closurecontext register="RDX" />
 * 		&lt;/register_info>
 * 		&lt;register_info versions="1.2">
 * 			...
 * 		&lt;/register_info>
 *	&lt;/golang> 
 * </pre>
 */
public class GoRegisterInfoManager {
	private static final String REGISTER_INFO_EXTERNAL_NAME = "Golang.register.info.file";

	private static class SingletonHolder {
		private static GoRegisterInfoManager instance = new GoRegisterInfoManager();
	}

	public static GoRegisterInfoManager getInstance() {
		return SingletonHolder.instance;
	}

	/**
	 * Returns a {@link GoRegisterInfo} instance for the specified {@link Language}.
	 * <p>
	 * If the language didn't define golang register info, a generic/empty instance will be
	 * returned that forces all parameters to be stack allocated.
	 * 
	 * @param lang {@link Language}
	 * @param goVer {@link GoVer}
	 * @return {@link GoRegisterInfo}, never null
	 */
	public synchronized GoRegisterInfo getRegisterInfoForLang(Language lang, GoVer goVer) {
		List<GoRegisterInfo> registerInfos = loadRegisterInfo(lang);
		for(GoRegisterInfo registerInfo : registerInfos) {
			if ( registerInfo.getValidVersions().contains(goVer)) {
				return registerInfo;
			}
		}
		
		int goSize = lang.getInstructionAlignment();
		Msg.warn(this, "Missing Golang register info for: %s, defaulting to abi0, size=%d"
				.formatted(lang.getLanguageID(), goSize));
		return getDefault(lang);
	}

	private List<GoRegisterInfo> loadRegisterInfo(Language lang) {
		try {
			ResourceFile f = DWARFUtil.getLanguageExternalFile(lang, REGISTER_INFO_EXTERNAL_NAME);
			if (f != null) {
				return read(f, lang);
			}
			Msg.warn(GoRegisterInfoManager.class,
				"Missing Golang register info file for: %s".formatted(lang.getLanguageID()));
		}
		catch (IOException e) {
			Msg.warn(GoRegisterInfoManager.class, "Failed to read Golang register info file",
				e);
		}
		return List.of();
	}

	//-------------------------------------------------------------------------------------------
	private List<GoRegisterInfo> read(ResourceFile f, Language lang)
			throws IOException {
		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
		try (InputStream fis = f.getInputStream()) {
			Document doc = sax.build(fis);
			Element rootElem = doc.getRootElement();
			return readFrom(rootElem, lang);
		}
		catch (JDOMException | IOException e) {
			Msg.error(GoRegisterInfo.class, "Bad Golang register info file " + f, e);
			throw new IOException("Failed to read Golang register info file " + f, e);
		}

	}

	@SuppressWarnings("unchecked")
	private List<GoRegisterInfo> readFrom(Element rootElem, Language lang) throws IOException {

		List<GoRegisterInfo> result = new ArrayList<>();
		for (Element regInfoElem : (List<Element>) rootElem.getChildren("register_info")) {
			GoRegisterInfo registerInfo = readRegInfoElement(regInfoElem, lang);
			result.add(registerInfo);
		}
		return result;
	}

	private GoRegisterInfo readRegInfoElement(Element regInfoElem, Language lang)
			throws IOException {
		GoVerSet validGoVersions =
			GoVerSet.parse(XmlUtilities.requireStringAttr(regInfoElem, "versions"));

		Element intRegsElem = regInfoElem.getChild("int_registers");
		Element floatRegsElem = regInfoElem.getChild("float_registers");
		Element stackElem = regInfoElem.getChild("stack");
		Element goRoutineElem = regInfoElem.getChild("current_goroutine");
		Element zeroRegElem = regInfoElem.getChild("zero_register");
		Element duffZeroElem = regInfoElem.getChild("duffzero");
		Element closureContextElem = regInfoElem.getChild("closurecontext");
		if (intRegsElem == null || floatRegsElem == null || stackElem == null ||
			goRoutineElem == null || zeroRegElem == null || duffZeroElem == null ||
			closureContextElem == null) {
			throw new IOException("Bad format");
		}

		List<Register> intRegs = parseRegListStr(intRegsElem.getAttributeValue("list"), lang);
		List<Register> floatRegs = parseRegListStr(floatRegsElem.getAttributeValue("list"), lang);

		int stackInitialOffset =
			XmlUtilities.parseBoundedIntAttr(stackElem, "initialoffset", 0, Integer.MAX_VALUE);
		int maxAlign =
			XmlUtilities.parseBoundedIntAttr(stackElem, "maxalign", 1, Integer.MAX_VALUE);

		Register currentGoRoutineReg =
			parseRegStr(goRoutineElem.getAttributeValue("register"), lang);
		Register zeroReg = parseRegStr(zeroRegElem.getAttributeValue("register"), lang);
		boolean zeroRegIsBuiltin =
			XmlUtilities.parseOptionalBooleanAttr(zeroRegElem, "builtin", false);
		
		Register duffzeroDest = parseRegStr(duffZeroElem.getAttributeValue("dest"), lang);
		Register duffzeroZero = parseRegStr(duffZeroElem.getAttributeValue("zero_arg"), lang);
		RegType duffzeroZeroType = parseRegTypeStr(duffZeroElem.getAttributeValue("zero_type"));

		Register closureContextReg =
			parseRegStr(closureContextElem.getAttributeValue("register"), lang);

		GoRegisterInfo registerInfo = new GoRegisterInfo(intRegs, floatRegs, stackInitialOffset,
			maxAlign, currentGoRoutineReg, zeroReg, zeroRegIsBuiltin, duffzeroDest, duffzeroZero,
			duffzeroZeroType, closureContextReg, validGoVersions);
		return registerInfo;
	}

	private GoRegisterInfo getDefault(Language lang) {
		int goSize = lang.getInstructionAlignment();
		return new GoRegisterInfo(List.of(), List.of(), goSize, goSize, null, null, false, null,
			null, RegType.INT, null, GoVerSet.ALL);
	}

	private List<Register> parseRegListStr(String s, Language lang) throws IOException {
		List<Register> result = new ArrayList<>();
		for (String regName : s.split(",")) {
			regName = regName.trim();
			if (regName.isEmpty()) {
				continue;
			}
			Register register = parseRegStr(regName, lang);
			if (register != null) {
				result.add(register);
			}
		}
		return result;
	}

	private Register parseRegStr(String regName, Language lang) throws IOException {
		if (regName == null || regName.isBlank()) {
			return null;
		}
		Register register = lang.getRegister(regName);
		if (register == null) {
			throw new IOException("Unknown register: " + regName);
		}
		return register;
	}

	private RegType parseRegTypeStr(String s) {
		return switch (Objects.requireNonNullElse(s, "int").toLowerCase()) {
			default -> RegType.INT;
			case "float" -> RegType.FLOAT;
		};

	}
}
