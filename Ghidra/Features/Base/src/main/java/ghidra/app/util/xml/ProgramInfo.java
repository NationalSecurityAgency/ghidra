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
package ghidra.app.util.xml;

import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

/**
 * This class stores values pulled from the
 * PROGRAM, INFO_SOURCE, and LANGUAGE tag inside a ghidra program XML file.
 * 
 * Please see PROGRAM.DTD
 * 
 * 
 */
public class ProgramInfo {
	/**The family name of the program's processor (eg, "Intel").*/
	public String family;
	/**The program's processor (eg, Processor.PROCESSOR_X86).*/
	public String processorName;
	/**The program's language id, e.g. "x86:LE:32:default".*/
	public LanguageID languageID;
	/**The program's compilerSpec id, e.g. "gcc".*/
	public CompilerSpecID compilerSpecID;
	/**The preferred name of the Program when loaded back into Ghidra.*/
	public String programName;
	/**The timestamp of when the XML file was created.*/
	public String timestamp;
	/**The ID of the user that created the XML file.*/
	public String user;
	/**The tool that generated the XML file (eg, "Ghidra", etc.).*/
	private String tool;
	/**This is the name of the tool normalized into known categories ("IDA-PRO" or "GHIDRA") if appropriate.*/
	private String normalizedExternalToolName;
	/** The XML version. @deprecated since version 2.1.*/
	public String version;
	/**The size of the addressing (eg, "32 bit"). @deprecated since version 2.1.*/
	public String addressModel;
	/**The endianess (eg, big or little).*/
	public String endian;
	/**The absolute path of where the original executable was imported.*/
	public String exePath;
	/**The format of the original executable (eg, PE or ELF).*/
	public String exeFormat;
	/**The image base of the program.*/
	public String imageBase;

	@Override
	public String toString() {
		return "processor=" + processorName + "\nfamily=" + family + "\ncompiler=" +
			compilerSpecID + "\n" + "address model=" + addressModel + "\nendian=" + endian +
			"\nprogram=" + programName;
	}

	/**whether the XmlMgr should process stack frames and references.*/
	public boolean shouldProcessStack() {
		return true;
	}

	/**
	 * Returns true if the tool was IDA-PRO.
	 * @return true if the tool was IDA-PRO
	 */
	boolean isIdaPro() {
		return "IDA-PRO".equalsIgnoreCase(this.normalizedExternalToolName);
	}

	boolean isGhidra() {
		return "GHIDRA".equalsIgnoreCase(this.normalizedExternalToolName);
	}

	private String translateCompiler(String compiler) {
		if (isIdaPro()) {
			return translateIDACompilerName(compiler);
		}
		return compiler;
	}

	public void setCompilerSpecID(String compiler) {
		this.compilerSpecID = null;
		if (compiler != null) {
			String translated = this.translateCompiler(compiler);
			CompilerSpecID cspec = new CompilerSpecID(translated);
			this.compilerSpecID = cspec;
		}
	}

	private String translateIDACompilerName(String compiler) {
		if ("Visual C++".equals(compiler)) {
			return "windows";
		}
		return compiler;
	}

	/**
	 * Returns tool field.  This is the name of the tool exactly as written in the XML being imported.
	 * @return tool field
	 */
	public String getTool() {
		return tool;
	}

	/**
	 * Sets tool field.
	 * Also sets normalizedExternalToolName to normalized tool names "IDA-PRO" or "GHIDRA" if appropriate, or just sets it to the value of tool.
	 */
	public void setTool(String tool) {

		this.tool = tool;
		this.normalizedExternalToolName = tool;

		if (this.tool != null && this.tool.toUpperCase().startsWith("IDA-PRO")) {
			this.normalizedExternalToolName = "IDA-PRO";
		}
		else if (this.tool != null && this.tool.toUpperCase().startsWith("GHIDRA")) {
			this.normalizedExternalToolName = null;  //"GHIDRA";  // null, not external
		}

	}

	/**
	 * Returns normalizedExternalToolName field.  This is the name of the tool normalized into known categories ("IDA-PRO" or "GHIDRA") if appropriate.
	 * @return normalizedExternalToolName
	 */
	public String getNormalizedExternalToolName() {
		return this.normalizedExternalToolName;
	}
}
