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
package ghidra.app.util.cparser.C;

import java.util.Arrays;

import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;

public class CParserUtils {

	private CParserUtils() {
		// utils class
	}

	/**
	 * Parse the given function signature text.  Any exceptions will be handled herein
	 * by showing an error dialog (null is returned in that case).
	 * 
	 * @param serviceProvider the service provider used to access DataTypeManagers
	 * @param program the program against which data types will be resolved
	 * @param signatureText the signature to parse
	 * @return the data type that is created as a result of parsing; null if there was a problem
	 * 
	 * @see #parseSignature(DataTypeManagerService, Program, String)
	 * @see #parseSignature(DataTypeManagerService, Program, String, boolean)
	 */
	public static FunctionDefinitionDataType parseSignature(ServiceProvider serviceProvider,
			Program program, String signatureText) {
		DataTypeManagerService service = serviceProvider.getService(DataTypeManagerService.class);
		return parseSignature(service, program, signatureText);
	}

	/**
	 * Parse the given function signature text.  Any exceptions will be handled herein
	 * by showing an error dialog (null is returned in that case).
	 * 
	 * @param service the service used to access DataTypeManagers or null to use only the program's
	 * data type manager.
	 * @param program the program against which data types will be resolved
	 * @param signatureText the signature to parse
	 * @return the data type that is created as a result of parsing; null if there was a problem
	 * 
	 * @see #parseSignature(DataTypeManagerService, Program, String, boolean)
	 */
	public static FunctionDefinitionDataType parseSignature(DataTypeManagerService service,
			Program program, String signatureText) {
		try {
			return parseSignature(service, program, signatureText, true);
		}
		catch (ParseException e) {
			// Can't happen, as we are passing 'true' above.  Just in case this changes, 
			// log the exception
			Msg.debug(CParserUtils.class,
				"Logging an exception that cannot happen (the code must have changed)", e);
			return null;
		}
	}

	/**
	 * Split function signature into three parts:
	 * [0]= part before function name
	 * [1]= function name
	 * [2]= parameter body after function name
	 * @param signature
	 * @return parts array or null if split failed
	 */
	private static String[] splitFunctionSignature(String signature) {

		int index = signature.lastIndexOf(')');
		if (index < 0) {
			return null;
		}
		int closureCount = 1;
		while (--index > 0) {
			char c = signature.charAt(index);
			if (c == ' ') {
				// ignore
			}
			else if (c == ')') {
				++closureCount;
			}
			else if (c == '(') {
				--closureCount;
			}
			else if (closureCount <= 0) {
				break;
			}
		}

		if (closureCount != 0) {
			return null;
		}

		String[] parts = new String[3];
		parts[2] = signature.substring(index + 1);

		signature = signature.substring(0, index + 1);

		int spaceIndex = signature.lastIndexOf(' ');
		if (spaceIndex <= 0) {
			return null;
		}

		parts[1] = signature.substring(spaceIndex + 1);
		parts[0] = signature.substring(0, spaceIndex);

		return parts;
	}

	/**
	 * Get a temporary name of a specified length (tttt....)
	 * @param length
	 * @return temporary name string
	 */
	private static String getTempName(int length) {
		char[] nameChars = new char[length];
		Arrays.fill(nameChars, 't');
		return new String(nameChars);
	}

	/**
	 * Parse the given function signature text.  Any exceptions will be handled herein
	 * by showing an error dialog (null is returned in that case).
	 * 
	 * @param service the service used to access DataTypeManagers or null to use only the program's
	 * data type manager.
	 * @param program the program against which data types will be resolved
	 * @param signatureText the signature to parse
	 * @param handleExceptions true signals that this method should deal with exceptions, 
	 *        showing error messages as necessary; false signals to throw any encountered
	 *        parsing exceptions.  This allows clients to perform exception handling that
	 *        better matches their workflow.
	 * @return the data type that is created as a result of parsing; null if there was a problem
	 */
	public static FunctionDefinitionDataType parseSignature(DataTypeManagerService service,
			Program program, String signatureText, boolean handleExceptions) throws ParseException {

		DataTypeManager[] dataTypeManagers = service != null ? getDataTypeManagers(service)
				: new DataTypeManager[] { program.getDataTypeManager() };

		CParser parser = new CParser(program.getDataTypeManager(), false, dataTypeManagers);

		String[] signatureParts = splitFunctionSignature(signatureText);
		if (signatureParts == null) {
			Msg.debug(CParserUtils.class,
				"Invalid signature: unable to isolate function name : " + signatureText);
			return null;
		}

		String replacedText =
			signatureParts[0] + " " + getTempName(signatureParts[1].length()) + signatureParts[2];

		DataType dt = null;
		try {
			// parse the signature
			dt = parser.parse(replacedText + ";");

			if (!(dt instanceof FunctionDefinitionDataType)) {
				return null;
			}

			// put back the old signature name
			dt.setName(signatureParts[1]);

			return (FunctionDefinitionDataType) dt;
		}
		catch (InvalidNameException | DuplicateNameException e) {
			// can't happen since we are calling setName() with the value that was 
			// previously set (this can change in the future if we ever modify the 
			// name before we restore it) 
			Msg.debug(CParserUtils.class,
				"Logging an exception that cannot happen (the code must have changed)", e);
		}
		catch (Throwable t) {
			if (!handleExceptions) {
				throw t;
			}

			String msg = handleParseProblem(t, signatureText);
			if (msg != null) {
				Msg.showError(CParserUtils.class, null, "Invalid Function Signature", msg);
			}
			else {
				Msg.debug(CParserUtils.class, "Error parsing signature: " + signatureText, t);
			}

		}

		return null;
	}

	private static DataTypeManager[] getDataTypeManagers(DataTypeManagerService service) {

		if (service == null) {
			return null;
		}

		DataTypeManager[] openDTmanagers = service.getDataTypeManagers();
		return openDTmanagers;
	}

	/**
	 * Given a throwable, attempt pull out the significant error parts to generate a 
	 * user-friendly error message.
	 * 
	 * @param t the throwable to examine, originating from the {@link CParser}.
	 * @param functionString the full function signature text that was parsed by the parser.
	 * @return a user-friendly error message, or null if this class did not know how to 
	 *         handle the given exception.
	 */
	public static String handleParseProblem(Throwable t, String functionString) {
		if (t instanceof TokenMgrError) {
			return generateTokenErrorMessage((TokenMgrError) t, functionString);
		}
		else if (t instanceof ParseException) {
			return generateParseExceptionMessage((ParseException) t, functionString);
		}
		return null;
	}

	private static String generateTokenErrorMessage(TokenMgrError e, String functionString) {

		// HACKY SMACKY: we have to parse the error message to get out the bits we 
		//               desire.  If we could control the TokeyMgrError.java file 
		//               generation, then we could put the fields in it that we need.

		String message = e.getMessage();

		int errorIndex = getTokenMgrErrorIndexOfInvalidText(message, functionString);
		if (errorIndex < 0) {
			errorIndex = getTokenMgrErrorIndexUsingErrorColumn(message);
		}

		if (errorIndex < 0) {
			return null;
		}

		return generateParsingExceptionMessage(e.getMessage(), errorIndex, functionString);
	}

	// the error message contains an 'after' text, which is the text that comes after the
	// invalid text
	private static int getTokenMgrErrorIndexOfInvalidText(String message, String functionString) {
		String invalidCharMarker = "after : ";
		int index = message.indexOf(invalidCharMarker);
		if (index >= 0) {
			String remainder = message.substring(index + invalidCharMarker.length());
			remainder = remainder.replaceAll("\"", "");
			return functionString.indexOf(remainder);
		}
		return -1;
	}

	// the error message contains a 'column' value that is the character column where
	// the error occurred
	private static int getTokenMgrErrorIndexUsingErrorColumn(String message) {
		String columnMarker = "column ";
		int index = message.indexOf(columnMarker);
		if (index >= 0) {
			String remainder = message.substring(index + columnMarker.length());
			int dotIndex = remainder.indexOf(".");
			String column = remainder.substring(0, dotIndex);

			try {
				return Integer.parseInt(column);
			}
			catch (NumberFormatException nfe) {
				// we tried
			}
		}
		return -1;
	}

	private static String generateParseExceptionMessage(ParseException pe, String functionString) {
		// HACKY SMACKY!....this code is done in lieu of actually putting good data in the 
		// exception itself...we should do that!
		if (pe.currentToken == null) {
			return null;
		}

		int errorIndex = pe.currentToken.beginColumn;
		if (errorIndex < 0) {
			return null;
		}

		return generateParsingExceptionMessage(pe.getMessage(), errorIndex, functionString);
	}

	private static String generateParsingExceptionMessage(String errorMessage, int errorIndex,
			String functionString) {
		String parseMessage = "";
		if (errorMessage != null) {

			// Handle lines that are as big as the screen:
			// -wrap on the given length
			// -remove newlines because the line wrapping utility always breaks on those
			parseMessage = errorMessage.replaceAll("\n", " ");
			parseMessage = HTMLUtilities.lineWrapWithHTMLLineBreaks(
				HTMLUtilities.escapeHTML(parseMessage), 80);
			parseMessage = "<br><br>" + parseMessage + "<br>";
		}

		StringBuffer successFailureBuffer = new StringBuffer();
		successFailureBuffer.append("<blockquote>");
		if (errorIndex == 0) {
			successFailureBuffer.append("<font color=\"red\"><b>");
			successFailureBuffer.append(HTMLUtilities.friendlyEncodeHTML(functionString));
			successFailureBuffer.append("</b></font>");
		}
		else {
			successFailureBuffer.append("<font color=\"black\">");
			successFailureBuffer.append(
				HTMLUtilities.friendlyEncodeHTML(functionString.substring(0, errorIndex)));
			successFailureBuffer.append("</font>");
			successFailureBuffer.append("<font color=\"red\"><b>");
			successFailureBuffer.append(
				HTMLUtilities.friendlyEncodeHTML(functionString.substring(errorIndex)));
			successFailureBuffer.append("</b></font>");
		}
		successFailureBuffer.append("</blockquote>");

		if (errorIndex == 0) {
			return "<html>Function signature parse failed" + parseMessage + "<br>" +
				successFailureBuffer;
		}
		return "<html>Function signature parse failed on token starting near character " +
			errorIndex + "<br>" + successFailureBuffer;
	}

}
