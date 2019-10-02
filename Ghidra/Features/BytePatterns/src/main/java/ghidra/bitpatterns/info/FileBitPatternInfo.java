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
package ghidra.bitpatterns.info;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import org.jdom.*;
import org.jdom.input.SAXBuilder;

import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

/**
 * An object of this class stores all the function bit pattern information for an executable.
 * It records the number of bytes and instructions for each category (first, pre, and return), as
 * well as the language ID and ghidraURL of the executable.  Using JAXB, objects of this class converted
 * to/from XML files for analysis and storage.
 */

public class FileBitPatternInfo {

	static final String XML_ELEMENT_NAME = "FileBitPatternInfo";

	private int numFirstBytes = 0;
	private int numFirstInstructions = 0;
	private int numPreBytes = 0;
	private int numPreInstructions = 0;
	private int numReturnBytes = 0;
	private int numReturnInstructions = 0;
	private String languageID = null;
	private String ghidraURL = null;
	private List<FunctionBitPatternInfo> funcBitPatternInfo;
	//possible TODO: Use SaveState instead of JAXB to do the XML serialization?

	/**
	 * Default no-arg constructor.  Used by JAXB for XML serialization.
	 */
	public FileBitPatternInfo() {
		funcBitPatternInfo = new ArrayList<FunctionBitPatternInfo>();
	}

	/**
	 * Get the number of bytes gathered, starting at the entry point of a function.
	 * @return number of first bytes
	 */
	public int getNumFirstBytes() {
		return numFirstBytes;
	}

	/**
	 * Set the number of bytes gathered, starting at the entry point of a function
	 * @param numFirstBytes number of bytes
	 */
	public void setNumFirstBytes(int numFirstBytes) {
		this.numFirstBytes = numFirstBytes;
	}

	/**
	 * Get the number of instructions gathered, starting with instruction at the 
	 * entry point of the function
	 * @return number of instructions 
	 */
	public int getNumFirstInstructions() {
		return numFirstInstructions;
	}

	/**
	 * Set the number of initial instructions gathered.
	 * @param numFirstInstructions number of instructions 
	 */
	public void setNumFirstInstructions(int numFirstInstructions) {
		this.numFirstInstructions = numFirstInstructions;
	}

	/**
	 * Get the number of bytes gathered immediately before (but not including) the entry point
	 * of a function
	 * @return number of bytes gathered
	 */
	public int getNumPreBytes() {
		return numPreBytes;
	}

	/**
	 * Set the number of bytes gathered immediately before (but not including) the entry point
	 * of a function
	 * @param numPreBytes number of bytes
	 */
	public void setNumPreBytes(int numPreBytes) {
		this.numPreBytes = numPreBytes;
	}

	/**
	 * Get the number of instructions gathered immediately before (but not including) a function start
	 * @return number of instructions
	 */
	public int getNumPreInstructions() {
		return numPreInstructions;
	}

	/**
	 * Set the number of instructions gathered immediately before (but not including) a function start
	 * 
	 * @param numPreInstructions number of instructions
	 */
	public void setNumPreInstructions(int numPreInstructions) {
		this.numPreInstructions = numPreInstructions;
	}

	/**
	 * Get the list of {@link FunctionBitPatternInfo} objects for the program (one object per function)
	 * @return List whose elements record information about each function start in the program
	 */
	public List<FunctionBitPatternInfo> getFuncBitPatternInfo() {
		return funcBitPatternInfo;
	}

	/**
	 * Set the list of {@link FunctionBitPatternInfo} objects for the program (one object per function)
	 * @param funcStartInfo List whose elements record information about each function start in the
	 * program
	 */
	public void setFuncBitPatternInfo(List<FunctionBitPatternInfo> funcBitPatternInfo) {
		this.funcBitPatternInfo = funcBitPatternInfo;
	}

	/**
	 * Get the language ID string of the program
	 * @return the language ID
	 */
	public String getLanguageID() {
		return languageID;
	}

	/**
	 * Set the language ID string of the program
	 * @param id the language id
	 */
	public void setLanguageID(String id) {
		this.languageID = id;
	}

	/**
	 * Set the GhidraURL of the program
	 * @param url the url
	 */
	public void setGhidraURL(String url) {
		this.ghidraURL = url;
	}

	/**
	 * Get the GhidraURL of the program
	 * @return the url
	 */
	public String getGhidraURL() {
		return ghidraURL;
	}

	/**
	 * Get the number of return bytes gathered, i.e., the number of bytes gathered immediately before
	 * (and including) a return instruction.
	 * @return number of return bytes
	 */
	public int getNumReturnBytes() {
		return numReturnBytes;
	}

	/**
	 * Set the number of return bytes, i.e., the number of bytes gathered immediately before
	 * (and including) a return instruction.
	 * @param numReturnBytes number of return bytes
	 */
	public void setNumReturnBytes(int numReturnBytes) {
		this.numReturnBytes = numReturnBytes;
	}

	/**
	 * Get the number of instructions immediately before (and including) a return instruction 
	 * @return number of return instructions
	 */
	public int getNumReturnInstructions() {
		return numReturnInstructions;
	}

	/**
	 * Set the number of instructions immediately before (and including) a return instruction
	 * @param numReturnInstructions number of return instructions
	 */
	public void setNumReturnInstructions(int numReturnInstructions) {
		this.numReturnInstructions = numReturnInstructions;
	}

	/**
	 * Converts this object into XML
	 * 
	 * @return new jdom {@link Element}
	 */
	public Element toXml() {
		Element result = new Element(XML_ELEMENT_NAME);
		XmlUtilities.setStringAttr(result, "ghidraURL", ghidraURL);
		XmlUtilities.setStringAttr(result, "languageID", languageID);
		XmlUtilities.setIntAttr(result, "numFirstBytes", numFirstBytes);
		XmlUtilities.setIntAttr(result, "numFirstInstructions", numFirstInstructions);
		XmlUtilities.setIntAttr(result, "numPreBytes", numPreBytes);
		XmlUtilities.setIntAttr(result, "numPreInstructions", numPreInstructions);
		XmlUtilities.setIntAttr(result, "numReturnBytes", numReturnBytes);
		XmlUtilities.setIntAttr(result, "numReturnInstructions", numReturnInstructions);

		Element funcBitPatternInfoListEle = new Element("funcBitPatternInfoList");
		for (FunctionBitPatternInfo fbpi : funcBitPatternInfo) {
			funcBitPatternInfoListEle.addContent(fbpi.toXml());
		}

		result.addContent(funcBitPatternInfoListEle);

		return result;
	}

	/**
	 * Creates a {@link FileBitPatternInfo} instance from XML.
	 * 
	 * @param e XML element to convert
	 * @return new {@link FileBitPatternInfo}, never null
	 * @throws IOException if file IO error or xml data problem
	 */
	public static FileBitPatternInfo fromXml(Element e) throws IOException {

		String ghidraURL = e.getAttributeValue("ghidraURL");
		String languageID = e.getAttributeValue("languageID");
		int numFirstBytes =
			XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numFirstBytes"));
		int numFirstInstructions =
			XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numFirstInstructions"));
		int numPreBytes = XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numPreBytes"));
		int numPreInstructions =
			XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numPreInstructions"));
		int numReturnBytes =
			XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numReturnBytes"));
		int numReturnInstructions =
			XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numReturnInstructions"));

		List<FunctionBitPatternInfo> funcBitPatternInfoList = new ArrayList<>();
		Element funcBitPatternInfoListEle = e.getChild("funcBitPatternInfoList");
		if (funcBitPatternInfoListEle != null) {
			for (Element childElement : XmlUtilities.getChildren(funcBitPatternInfoListEle,
				FunctionBitPatternInfo.XML_ELEMENT_NAME)) {
				funcBitPatternInfoList.add(FunctionBitPatternInfo.fromXml(childElement));
			}
		}

		FileBitPatternInfo result = new FileBitPatternInfo();
		result.setFuncBitPatternInfo(funcBitPatternInfoList);
		result.setGhidraURL(ghidraURL);
		result.setLanguageID(languageID);
		result.setNumFirstBytes(numFirstBytes);
		result.setNumFirstInstructions(numFirstInstructions);
		result.setNumPreBytes(numPreBytes);
		result.setNumPreInstructions(numPreInstructions);
		result.setNumReturnBytes(numReturnBytes);
		result.setNumReturnInstructions(numReturnInstructions);

		return result;
	}

	/**
	 * Converts this object to XML and writes it to the specified file.
	 * 
	 * @param destFile name of xml file to create
	 * @throws IOException if file io error
	 */
	public void toXmlFile(File destFile) throws IOException {
		Element rootEle = toXml();
		Document doc = new Document(rootEle);

		XmlUtilities.writePrettyDocToFile(doc, destFile);
	}

	/**
	 * Creates a {@link FileBitPatternInfo} instance from a XML file.
	 * 
	 * @param inputFile name of xml file to read
	 * @return new {@link FileBitPatternInfo} instance, never null
	 * @throws IOException if file io error or xml data format problem 
	 */
	public static FileBitPatternInfo fromXmlFile(File inputFile) throws IOException {
		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
		try (InputStream fis = new FileInputStream(inputFile)) {
			Document doc = sax.build(fis);
			Element rootElem = doc.getRootElement();
			return fromXml(rootElem);
		}
		catch (JDOMException | IOException e) {
			Msg.error(FileBitPatternInfo.class, "Bad file bit pattern file " + inputFile, e);
			throw new IOException("Failed to read file bit pattern " + inputFile, e);
		}

	}
}
