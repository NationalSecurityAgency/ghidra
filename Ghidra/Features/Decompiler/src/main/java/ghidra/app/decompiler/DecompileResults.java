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
package ghidra.app.decompiler;

import java.io.InputStream;

import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Class for getting at the various structures returned
 * by the decompiler.  Depending on how the DecompInterface
 * was called, you can get C code (with markup), the
 * function' syntax tree, the prototype, etc.
 * 
 * To check if the decompileFunction call completed normally
 * use the decompileCompleted method.  If this returns false,
 * the getErrorMessage method may contain a useful error
 * message.  Its also possible that getErrorMessage will
 * return warning messages, even if decompileFunction did
 * complete.
 * 
 * To get the resulting C code, marked up with XML in terms
 * of the lines and tokens, use the getCCodeMarkup method.
 * 
 * To get the resulting C code just as a straight String,
 * use the getDecompiledFunction method which returns a
 * DecompiledFunction.  Off of this, you can use the getC
 * method to get the raw C code as a String or use the
 * getSignature method to get the functions prototype as
 * a String.
 * 
 * To get the syntax tree use the getHighFunction method.
 * 
 * 
 *
 */
public class DecompileResults {
	private Function function; // Function to which results pertain
	private Language language;
	private CompilerSpec compilerSpec;
	private PcodeDataTypeManager dtmanage;
	private HighFunction hfunc; // HighFunction parsed from xml
	private HighParamID hparamid; //Parameter ID information
	private ClangTokenGroup docroot; // C code parsed from XML
	private String errMsg; // Error message from decompiler
	private DecompileProcess.DisposeState processState;

	public DecompileResults(Function f, Language language, CompilerSpec compilerSpec,
			PcodeDataTypeManager d, String e, InputStream raw,
			DecompileProcess.DisposeState processState) {
		function = f;
		this.language = language;
		this.compilerSpec = compilerSpec;
		dtmanage = d;
		errMsg = e;
		hfunc = null;
		hparamid = null;
		docroot = null;
		//dumpResults(raw);
		parseRawString(raw);
	}

//	private void dumpResults(String raw) {
//		if (raw == null) {
//			return;
//		}
//		try {
//			File tmpFile = File.createTempFile("decomp", ".xml");
//			OutputStream out = new BufferedOutputStream(new FileOutputStream(tmpFile));
//			out.write(raw.getBytes());
//			out.flush();
//			out.close();
//			Msg.info(this, "Dumped decompile data to: " + tmpFile);
//		}
//		catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//	}

	/**
	 * Returns true if the decompilation producing these
	 * results completed without aborting.  If it was
	 * aborted, there will be no real results in this
	 * object, and an error message should be available via
	 * getErrorMessage.
	 * @return true if the decompilation completed.
	 */
	public boolean decompileCompleted() {
		return ((hfunc != null) || (hparamid != null));
	}

	public Function getFunction() {
		return function;
	}

	/**
	 * If the action producing this set of decompiler results
	 * didn't complete, this method can be used to determine
	 * if the action was halted because its timer expired
	 * (as opposed to an error, a crash, or being explicitly
	 * cancelled).
	 * @return true if the timer cancelled these results
	 */
	public boolean isTimedOut() {
		return processState == DecompileProcess.DisposeState.DISPOSED_ON_TIMEOUT;
	}

	/**
	 * If the action producing this set of decompiler results
	 * didn't complete, this method can be used to determine
	 * if the action was explicitly cancelled (as opposed
	 * to an error, a timeout, or a crash).
	 * @return true if these results were explicitly cancelled
	 */
	public boolean isCancelled() {
		return processState == DecompileProcess.DisposeState.DISPOSED_ON_CANCEL;
	}

	/**
	 * If the action producing this set of decompiler results
	 * didn't complete, this method can be used to determine
	 * if the decompiler executable was not found or failed to start properly.
	 * @return true if the decompiler executable was not found.
	 */
	public boolean failedToStart() {
		return processState == DecompileProcess.DisposeState.DISPOSED_ON_STARTUP_FAILURE;
	}

	/**
	 * Return any error message associated with the
	 * decompilation producing these results.  Generally,
	 * there will only be an error if the decompilation was
	 * aborted for some reason, but there could conceivably
	 * be warnings obtainable via this method, even if the
	 * decompilation did complete.
	 * @return any error message associated with these results
	 */
	public String getErrorMessage() {
		return errMsg;
	}

	/**
	 * Get the high-level function structure associated
	 * with these decompilation results, or null if there
	 * was an error during decompilation
	 * @return the resulting HighFunction object
	 */
	public HighFunction getHighFunction() {
		return hfunc;
	}

	/**
	 * Get the high-level function structure associated
	 * with these decompilation results, or null if there
	 * was an error during decompilation
	 * @return the resulting HighParamID object
	 */
	public HighParamID getHighParamID() {
		return hparamid;
	}

	/**
	 * Get the marked up C code associated with these
	 * decompilation results. If there was an error, or
	 * code generation was turned off, retur null
	 * @return the resulting root of C markup
	 */
	public ClangTokenGroup getCCodeMarkup() {
		return docroot;
	}

	/**
	 * Converts the C code results into an unadorned string.
	 * The returned object contains both the whole function
	 * and just the prototype as separate strings containing
	 * raw C code
	 * @return a DecompiledFunction object
	 */
	public DecompiledFunction getDecompiledFunction() {
		if (docroot == null) {
			return null;
		}
		PrettyPrinter printer = new PrettyPrinter(function, docroot);
		return printer.print(true);
	}

	private void parseRawString(InputStream rawxml) {
		if (rawxml == null) {
			return;
		}
		XmlPullParser parser = null;
		try {
			try {
				parser =
					HighFunction.stringTree(
						rawxml,
						HighFunction.getErrorHandler(this, "decompiler results for function at " +
							function.getEntryPoint()));
				hfunc = null;
				hparamid = null;
				docroot = null;
				parser.start("doc");
				while(parser.peek().isStart()) {
					XmlElement el = parser.peek();
					if (el.getName().equals("function")) {
						if (hfunc ==  null) {
							hfunc = new HighFunction(function, language, compilerSpec, dtmanage);
							hfunc.readXML(parser);
						}
						else {		// TODO: This is an ugly kludge to get around duplicate XML tag names
							docroot = ClangXML.buildClangTree(parser, hfunc);
							if (docroot == null) {
								errMsg = "Unable to parse C (xml)";
							}							
						}
					}
					else if (el.getName().equals("parammeasures")) {
						hparamid = new HighParamID(function, language, compilerSpec, dtmanage);
						hparamid.readXML(parser);
					}
					else {
						errMsg = "Unknown decompiler tag: "+el.getName();
						return;
					}
				}
			}
			catch (PcodeXMLException e) {		// Error while walking the DOM
				errMsg = e.getMessage();
				hfunc = null;
				hparamid = null;
				return;
			}
			catch (RuntimeException e) {		// Exception from the raw parser
				errMsg = e.getMessage();
				hfunc = null;
				hparamid = null;
				return;
			}
		}
		finally {
			if (parser != null) {
				parser.dispose();
			}
		}
	}
}
