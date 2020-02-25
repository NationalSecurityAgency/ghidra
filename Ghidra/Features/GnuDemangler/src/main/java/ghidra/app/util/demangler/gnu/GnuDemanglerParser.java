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
package ghidra.app.util.demangler.gnu;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.demangler.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;

public class GnuDemanglerParser {

	private static final String CONSTRUCTION_VTABLE_FOR = "construction vtable for ";
	private static final String VTT_FOR = "VTT for ";
	private static final String VTABLE_FOR = "vtable for ";
	private static final String TYPEINFO_NAME_FOR = "typeinfo name for ";
	private static final String TYPEINFO_FN_FOR = "typeinfo fn for ";
	private static final String TYPEINFO_FOR = "typeinfo for ";
	private static final String REFERENCE_TEMPORARY_FOR = "reference temporary for ";
	private static final String GUARD_VARIABLE_FOR = "guard variable for ";
	private static final String COVARIANT_RETURN_THUNK = "covariant return thunk";
	private static final String VIRTUAL_THUNK = "virtual thunk";
	private static final String NONVIRTUAL_THUNK = "non-virtual thunk";

	private static final String NAMESPACE_DELIMITER = "::";

	private SpecialPrefixHandler getSpecialPrefixHandler(String demangled) {

		if (demangled.startsWith(VTT_FOR)) {
			return new AddressTableHandler(demangled, VTT_FOR);
		}
		if (demangled.startsWith(VTABLE_FOR)) {
			return new AddressTableHandler(demangled, VTABLE_FOR);
		}
		if (demangled.startsWith(TYPEINFO_NAME_FOR)) {
			return new TypeInfoNameHandler(demangled, TYPEINFO_NAME_FOR);
		}
		if (demangled.startsWith(TYPEINFO_FOR)) {
			return new AddressTableHandler(demangled, TYPEINFO_FOR);
		}
		if (demangled.startsWith(TYPEINFO_FN_FOR)) {
			return new AddressTableHandler(demangled, TYPEINFO_FN_FOR);
		}
		if (demangled.startsWith(CONSTRUCTION_VTABLE_FOR)) {
			return new ConstructionVTableHandler(demangled, CONSTRUCTION_VTABLE_FOR);
		}

		return null;
	}

	private OperatorHandler getOperatorHandler(String demangled) {

		OperatorHandler handler = new OverloadOperatorHandler();
		if (handler.matches(demangled)) {
			return handler;
		}

		handler = new ConversionOperatorHandler();
		if (handler.matches(demangled)) {
			return handler;
		}

		handler = new NewOrDeleteOperatorHandler();
		if (handler.matches(demangled)) {
			return handler;
		}

		return null;
	}

	/**
	 * <pre>
	 * Syntax: bob(const(Rect &, bool))
	 *
	 * pattern: 'const' with surrounding '()' with a capture group for the contents
	 * </pre>
	 */
	private static final Pattern CONST_FUNCTION_PATTERN = Pattern.compile("const\\((.*)\\)");

	/**
	 * <pre>
	 * Syntax: bob((Rect &, unsigned long))
	 *
	 * pattern: optional spaces followed by '()' with a capture group for the contents of the
	 *          parens
	 * note:    this pattern is used for matching the arguments string, in the above example it
	 *          would be: (Rect &, unsigned long)
	 * </pre>
	 */
	private static final Pattern UNNECESSARY_PARENS_PATTERN = Pattern.compile("\\s*\\((.*)\\)\\s*");

	/**
	 * <pre>
	 * Syntax: 	bob(short (&)[7])
	 * 			bob(int const[8] (*) [12])
	 *
	 * 			   typename[optional '*']<space>(*|&)[optional spaces][optional value]
	 *
	 * pattern:
	 * 				-a word
	 * 				-followed by a space
	 * 				-*optional: any other text (e.g., const[8])
	 * 				-followed by '()' that contain a '&' or a '*'
	 * 				-followed by one or more '[]' with optional interior text
	 * </pre>
	 */
	private static final Pattern ARRAY_POINTER_REFERENCE_PATTERN =
		Pattern.compile("([\\w:]+)\\*?\\s(.*)\\(([&*])\\)\\s*((?:\\[.*?\\])+)");

	/**
	 * <pre>
	 * Syntax: bob(short (&)[7])
	 *
	 * 			   (*|&)[optional spaces][optional value]
	 *
	 * pattern: '()' that contain a '&' or a '*' followed by '[]' with optional text; a capture
	 *          group for the contents of the parens
	 * </pre>
	*/
	private static final Pattern ARRAY_POINTER_REFERENCE_PIECE_PATTERN =
		Pattern.compile("\\(([&*])\\)\\s*\\[.*?\\]");

	/**
	* <pre>
	* Syntax: (unsigned)4294967295
	*
	* 			   (some text)[optional space]1 or more characters
	*
	* Regex:
	*
	* pattern:
	* 			-parens containing text
	* 			--the text can have "::" namespace separators (this is in a non-capturing group) and
	*             must be followed by more text
	*           --the text can have multiple words, such as (unsigned long)
	*           -optional space
	*           -optional '-' character
	* 			-followed by more text (with optional spaces)
	* </pre>
	*/
	private static final Pattern CAST_PATTERN =
		Pattern.compile("\\((?:\\w+\\s)*\\w+(?:::\\w+)*\\)\\s*-*\\w+");

	private static final String OPERATOR = "operator";

	/**
	 * <pre>
	 * Syntax: 
	 *         Magick::operator<(Magick::Coordinate const&, Magick::Coordinate const&)
	 * 		   std::basic_istream<char, std::char_traits<char> >& std::operator>><char, std::char_traits<char> >(std::basic_istream<char, std::char_traits<char> >&, char&)
	 * 
	 * 		  [return_type] operator opeartor_character(s) (opeartor_params)
	 *
	 * Regex:
	 * 
	 * pattern:
	 * 			-maybe a return type
	 * 			-operator
	 * 			-operator character(s)
	 *          -parameters
	 * </pre>
	 * 
	 * 
	 */
	private static final Pattern OVERLOAD_OPERATOR_PATTERN =
		createOverloadedOperatorPattern();

	/**
	* <pre>
	* Syntax: std::integral_constant<bool, false>::operator bool() const
	*         Magick::Color::operator std::basic_string<char, std::char_traits<char>, std::allocator<char> >() const
	*         
	* pattern:
	* 			-operator
	* 			-space
	*           -keyword for cast type
	*           -optional keywords
	*
	* </pre>
	*/
	private static final Pattern CONVERSION_OPERATOR_PATTERN =
		Pattern.compile("(.*" + OPERATOR + ") (.*)\\(\\).*");

	/**
	* <pre>
	* Syntax: operator new(unsigned long)
	*         operator new(void*)
	*         operator new[](void*)
	*
	* pattern:
	* 			-operator
	* 			-space
	*           -keyword 'new' or 'delete'
	*           -optional array brackets
	*           -optional parameters
	*
	* </pre>
	*/
	private static final Pattern NEW_DELETE_OPERATOR_PATTERN =
		Pattern.compile("(.*" + OPERATOR + ") (new|delete)(\\[\\])?\\((.*)\\).*");

	private static final String LAMBDA = "lambda";

	// TODO docme
	// {lambda(void const*, unsigned int)#1}
	// grab: 
	// 1 - full text
	// 2 - params
	// 3 - trailing id
	private static final Pattern LAMBDA_PATTERN =
		Pattern.compile(".*(\\{" + LAMBDA + "\\((.*)\\)(#\\d+)\\})");

	// TODO docme
	private static final Pattern DECLTYPE_RETURN_TYPE_PATTERN =
		Pattern.compile("decltype \\(.*\\)");

	// note: the '?' after the .*   this is there to allow the trailing digits to match as many as
	// possible
	private static final Pattern ENDS_WITH_DIGITS_PATTERN = Pattern.compile("(.*?)\\d+");

	private static final String SPACE = " ";
	private static final String VAR_ARGS = "...";

	private static final String CONST_KEYWORD = " const";

	private static final String ANONYMOUS_NAMESPACE = "\\(anonymous namespace\\)";
	private static final String ANONYMOUS_NAMESPACE_FIXUP = "anonymous_namespace";

	private GnuDemanglerNativeProcess process;

	public GnuDemanglerParser(GnuDemanglerNativeProcess process) {
		this.process = process;
	}

	private static Pattern createOverloadedOperatorPattern() {

		//@formatter:off
		Set<String> operators = new HashSet<>(Set.of(
			"++", "--",
			"+", "-", "*", "/", "%",
			"==", "!=", ">", "<", ">=", "<=",
			"&", "|", ">>", "<<", "~", "^",
			"&&", "||", "!",
			"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", ">>=", "<<=",
			","
		));
		//@formatter:on

		CollectionUtils.transform(operators, Pattern::quote);
		String alternated = StringUtils.join(operators, "|");
		return Pattern.compile("(.*" + OPERATOR + "(" + alternated + ").*)\\s*(\\(.*\\))(.*)");

	}

	public DemangledObject parse(String mangled, String demangled) {

		OperatorHandler operatorHandler = getOperatorHandler(demangled);
		if (operatorHandler != null) {
			return operatorHandler.build();
		}

		SpecialPrefixHandler handler = getSpecialPrefixHandler(demangled);
		if (handler != null) {
			try {
				String toParse = handler.getParent();
				DemangledObject dobj = parseParts(mangled, toParse);
				DemangledObject specialPrefixDobj = handler.build(dobj);
				return specialPrefixDobj;
			}
			catch (Exception e) {
				throw new RuntimeException(
					"Unexpected problem parsing " + demangled + " from mangled string: " + mangled,
					e);
			}
		}

		try {

			DemangledObject dobj = doParse(mangled, demangled);
			return dobj;
		}
		catch (Exception e) {
			throw new RuntimeException(
				"Unexpected problem parsing " + demangled + " from mangled string: " + mangled, e);
		}
	}

	public DemangledObject parseParts(String mangled, String demangled) throws IOException {

		DemangledObject dobj = null;
		List<String> nsParts = toNamespaceParts(demangled);
		for (String part : nsParts) {
			DemangledObject newDobj = doParse(mangled, part);
			if (dobj != null) {
				newDobj.setNamespace(dobj);
			}
			dobj = newDobj;
		}

		return dobj;
	}

	// TODO convert to use scanner; maybe delete scanner
	private List<String> toNamespaceParts(String s) {

		List<String> parts = new ArrayList<>();
		int nextStart = 0;
		int colon = 0;
		int ignoreCount = 0; // templates and parameters
		int n = s.length();
		for (int i = 0; i < n; i++) {
			char c = s.charAt(i);
			if (c == '<' || c == '(') {
				ignoreCount++;
				continue;
			}

			if (c == '>' || c == ')') {
				ignoreCount--;
				continue;
			}

			if (ignoreCount != 0) {
				continue;
			}

			if (c == ':') {
				if (++colon == 2) {
					parts.add(s.substring(nextStart, i - 1));
					nextStart = i + 1;
					colon = 0;
				}
				continue;
			}
			colon = 0;

			if (c == ' ') {
				parts.add(s.substring(nextStart, i));
				nextStart = i + 1;
			}
		}

		if (nextStart < n) {
			parts.add(s.substring(nextStart));
		}

		return parts;
	}

	private DemangledObject doParse(String mangled, String demangled) throws IOException {

		// remove spaces from anonymous namespace strings
		demangled = demangled.replaceAll(ANONYMOUS_NAMESPACE, ANONYMOUS_NAMESPACE_FIXUP);

		if (mangled != null && mangled.startsWith("_ZZ")) {
			return parseItemInNamespace(demangled, "");
		}
		if (demangled.startsWith(GUARD_VARIABLE_FOR)) {
			return parseItemInNamespace(demangled, GUARD_VARIABLE_FOR);
		}
		if (demangled.startsWith(REFERENCE_TEMPORARY_FOR)) {
			return parseItemInNamespace(demangled, REFERENCE_TEMPORARY_FOR);
		}

		if (demangled.startsWith(NONVIRTUAL_THUNK) || // _ZTh
			demangled.startsWith(VIRTUAL_THUNK) || // _ZTv
			demangled.startsWith(COVARIANT_RETURN_THUNK)) {// _ZTc

			return parseThunk(mangled, demangled);
		}

		ParameterLocator paramLocator = new ParameterLocator(demangled);
		if (!paramLocator.hasParameters()) {
			return parseVariable(demangled);
		}

		int paramStart = paramLocator.getParamStart();
		int paramEnd = paramLocator.getParamEnd();
		if (paramStart + 1 == demangled.indexOf(')')) {//check for overloaded 'operator()'
			int pos = paramStart - "operator".length();
			if (pos >= 0 && demangled.indexOf("operator") == pos) {
				paramStart = demangled.indexOf('(', paramStart + 1);
				paramEnd = demangled.lastIndexOf(')');
			}
		}

		String parameterString = demangled.substring(paramStart + 1, paramEnd).trim();
		List<DemangledDataType> parameters = parseParameters(parameterString);

		int prefixEndPos = paramStart;

		String chargeType = null;
		if (demangled.charAt(paramStart - 1) == ']') {//skip the GNU charge type...
			int sqBracketStartPos = backIndexOf(demangled, paramStart - 1, '[');
			//
			// This case would include operator_new[] and operator_delete[]
			// check to see if empty brackets exists
			//
			if (sqBracketStartPos != prefixEndPos - 2) {
				chargeType = demangled.substring(sqBracketStartPos, paramStart);
				prefixEndPos = sqBracketStartPos;
			}
		}

		String prefix = demangled.substring(0, prefixEndPos).trim();
		prefix = fixupInternalSeparators(prefix);

		int nameStartPos = backIndexOf(prefix, prefix.length() - 1, ' ');
		if (nameStartPos == -1) {
			throw new RuntimeException();
		}
		String name = prefix.substring(nameStartPos, prefix.length()).trim();
		if (chargeType != null) {
			name += chargeType;
		}

		DemangledFunction method = new DemangledMethod((String) null);
		String simpleName = name;
		LambdaName lambdaName = getLambdaName(demangled);
		if (lambdaName != null) {
			String uniqueName = lambdaName.getFullText();
			String fullLambda = fixupInternalSeparators(uniqueName);
			simpleName = name.replace("{lambda", fullLambda);
			method = new DemangledLambda(null);
			method.setSignature(lambdaName.getFullText());
		}

		// For GNU, we cannot leave the return type as null, because the DemangleCmd will fill in
		// pointer to the class to accommodate windows demangling
		method.setReturnType(new DemangledDataType("undefined"));
		for (DemangledDataType parameter : parameters) {
			method.addParameter(parameter);
		}

		setNameAndNamespace(method, simpleName);

		// TODO this should be handled somewhere else; verify it is still executed
		if (method.getName().startsWith("operator")) {
			char ch = method.getName().charAt("operator".length());
			if (!Character.isLetterOrDigit(ch)) {
				method.setOverloadedOperator(true);
			}
		}

		// check for return type
		if (nameStartPos > 0) {

			String returnType = prefix.substring(0, nameStartPos);
			setReturnType(method, returnType);
		}
		return method;
	}

	private void setReturnType(DemangledFunction method, String returnType) {

		if (DECLTYPE_RETURN_TYPE_PATTERN.matcher(returnType).matches()) {
			// Not sure yet if there is any information we wish to recover from this pattern.
			// Sample: decltype (functionName({parm#1}, (float)[42c80000])) 
			return;
		}

		method.setReturnType(parseDataType(returnType));
	}

	private LambdaName getLambdaName(String name) {
		Matcher matcher = LAMBDA_PATTERN.matcher(name);
		if (!matcher.matches()) {
			return null;
		}

		String fullText = matcher.group(1);
		String params = matcher.group(2);
		String trailing = matcher.group(3);
		return new LambdaName(fullText, params, trailing);
	}

	private DemangledObject parseThunk(String mangled, String demangled) throws IOException {
		int index = mangled.indexOf('_', 1);
		if (index < 0) {
			return null;
		}

		if (demangled.startsWith(VIRTUAL_THUNK) ||
			demangled.startsWith(COVARIANT_RETURN_THUNK)) {
			// skip second constant for virtual thunk
			index = mangled.indexOf('_', ++index);
			if (index < 0) {
				return null;
			}
		}

		String referencedMangledName = "_Z" + mangled.substring(index + 1);
		String referencedDemangledName = process.demangle(referencedMangledName);
		if (referencedMangledName.equals(referencedDemangledName) ||
			referencedDemangledName.length() == 0) {
			return null;
		}

		DemangledObject refObj = parse(referencedMangledName, referencedDemangledName);
		if (!(refObj instanceof DemangledFunction)) {
			return null;
		}
		refObj.setMangledString(referencedMangledName);
		refObj.setSignature(referencedDemangledName);

		// mark referenced function as a thiscall
		((DemangledFunction) refObj).setCallingConvention(
			CompilerSpec.CALLING_CONVENTION_thiscall);

		// (SCR 9800) Need to add support for Covariant Return Thunks which will 
		// allow the return type to differ from the underlying thunked function

		DemangledThunk thunkObj = new DemangledThunk((DemangledFunction) refObj);

		if (demangled.startsWith(COVARIANT_RETURN_THUNK)) {
			thunkObj.setCovariantReturnThunk();
		}

		index = demangled.indexOf(" to ");
		if (index > 0) {
			thunkObj.setSignaturePrefix(demangled.substring(0, index + 4));
		}

		return thunkObj;
	}

	// TODO move this into handler?
	private DemangledObject parseConversionOperator(Matcher matcher) {

		// this will yield:
		// fullName: 		NS1::Foo::operator
		// fullReturnType:  std::string
		String fullName = matcher.group(1);// group 0 is the entire match string
		String fullReturnType = matcher.group(2);

		boolean isConst = false;
		int index = fullReturnType.indexOf(CONST_KEYWORD);
		if (index != -1) {
			fullReturnType = fullReturnType.replace(CONST_KEYWORD, "");
			isConst = true;
		}

		DemangledMethod method = new DemangledMethod((String) null);
		DemangledDataType returnType = createDataType(fullReturnType);
		if (isConst) {
			returnType.setConst();
		}
		method.setReturnType(returnType);

		// 'conversion operator' syntax is 'operator <name/type>()'
		// assume fullName endsWith '::operator'
		int operatorIndex = fullName.lastIndexOf("::operator");
		String namespace = fullName.substring(0, operatorIndex);

		String templatelessNamespace = stripOffTemplates(namespace);
		setNamespace(method, templatelessNamespace);

		// shortReturnType: string
		String templatelessReturnType = stripOffTemplates(fullReturnType);
		SymbolPath path = new SymbolPath(templatelessReturnType);
		String shortReturnTypeName = path.getName();

		//
		// The preferred name: 'operator basic_string()'
		//
		// Ghidra does not allow spaces in the name or extra parens. So, make a name that is
		// as clear as possible in describing the construct.
		//
		method.setName("operator.cast.to." + shortReturnTypeName);

		method.setSignature(fullName + " " + fullReturnType);
		method.setOverloadedOperator(true);

		return method;
	}

	// TODO move this into handler?
	private DemangledObject parseNewOrDeleteOperator(Matcher matcher) {

		String operatorText = matcher.group(1);// group 0 is the entire match string
		String operatorName = matcher.group(2);
		String arrayBrackets = matcher.group(3);
		String parametersText = matcher.group(4);

		DemangledMethod method = new DemangledMethod((String) null);
		method.setOverloadedOperator(true);
		DemangledDataType returnType = new DemangledDataType("void");
		if (operatorName.startsWith("new")) {
			returnType.incrementPointerLevels();
		}

		method.setReturnType(returnType);

		// 'new operator' syntax is 'operator <name/type>()', where the
		// operator itself could be in a class namespace
		setNameAndNamespace(method, operatorText);

		List<DemangledDataType> parameters = parseParameters(parametersText);
		for (DemangledDataType parameter : parameters) {
			method.addParameter(parameter);
		}

		//
		// The preferred name: 'operator new()'
		//
		// Ghidra does not allow spaces in the name or extra parens. So, make a name that is
		// as clear as possible in describing the construct.
		//
		String name = operatorName;
		if (arrayBrackets != null) {
			name += "[]";
		}
		method.setName("operator." + name);

		method.setSignature(operatorText + " " + operatorName);

		return method;
	}

	private DemangledDataType createDataType(String fullReturnType) {
		DemangledDataType parsedDataType = parseDataType(fullReturnType);
		return parsedDataType;
	}

	// TODO can this use a scanner?
	private String stripOffTemplates(String string) {
		StringBuilder buffy = new StringBuilder();
		int templateCount = 0;
		for (int i = 0; i < string.length(); i++) {
			char c = string.charAt(i);
			if (c == '<') {
				templateCount++;
				continue;
			}
			else if (c == '>') {
				templateCount--;
				continue;
			}

			if (templateCount == 0) {
				buffy.append(c);
			}
		}
		return buffy.toString();
	}

	private DemangledObject parseItemInNamespace(String demangled,
			String prefix) {

		String itemText = demangled.substring(prefix.length()).trim();
		int pos = itemText.lastIndexOf(NAMESPACE_DELIMITER);
		if (pos == -1) {
			throw new RuntimeException();
		}

		String parentText = itemText.substring(0, pos);
		DemangledObject parent = parse(null, parentText);
		if (parent == null) {
			return null;
		}

		if (itemText.endsWith(CONST_KEYWORD)) {
			// TODO add trim() when tests are passing
			itemText = itemText.substring(0, itemText.length() - CONST_KEYWORD.length());
			parent.setConst(true);
		}

		String name = itemText.substring(pos + 2);
		ParameterLocator paramLocator = new ParameterLocator(name);
		if (paramLocator.hasParameters()) {

			// TODO refactor this out to a method when tests passing
			int paramStart = paramLocator.getParamStart();
			int paramEnd = paramLocator.getParamEnd();
			String nameOnly = name.substring(0, paramStart);
			DemangledMethod method = new DemangledMethod(nameOnly);
			String parameterString = name.substring(paramStart + 1, paramEnd).trim();
			List<DemangledDataType> parameters = parseParameters(parameterString);
			method.setReturnType(new DemangledDataType("undefined"));
			for (DemangledDataType parameter : parameters) {
				method.addParameter(parameter);
			}
			setNamespace(parent, method);
			return method;
		}

		DemangledVariable variable = new DemangledVariable(name);
		setNamespace(parent, variable);
		return variable;
	}

	private void setNamespace(DemangledObject parent, DemangledObject child) {

		DemangledType namespace = null;
		if (parent instanceof DemangledFunction) {
			DemangledFunction dfun = (DemangledFunction) parent;
			namespace = new DemangledFunctionType(dfun.toNamespaceName(),
				dfun.getSignature(false));
		}
		else {
			namespace = new DemangledType(parent.getName());
		}

		namespace.setNamespace(parent.getNamespace());
		child.setNamespace(namespace);
	}

	/**
	 * Replaces all SPACES and COLONS inside of groups (templates/parentheses) 
	 * with UNDERSCORES and DASHES, respectively
	 */
	private String fixupInternalSeparators(String name) {
		StringBuilder buffer = new StringBuilder();
		int enclosingLevel = 0;
		char last = '\u0000';
		for (int i = 0; i < name.length(); ++i) {
			char ch = name.charAt(i);
			if (ch == '<' || ch == '(') {
				++enclosingLevel;
			}
			else if ((ch == '>' || ch == ')') && enclosingLevel != 0) {
				--enclosingLevel;
			}

			if (enclosingLevel > 0 && ch == ' ') {
				char next = (i + 1) < name.length() ? name.charAt(i + 1) : '\u0000';
				if (isSurroundedByCharacters(last, next)) {
					// separate words with a value so they don't run together; drop the other spaces
					buffer.append('_');
				}
			}
			else if (enclosingLevel > 0 && ch == ':') {
				buffer.append('-');
			}
			else {
				buffer.append(ch);
			}

			last = ch;
		}
		return buffer.toString().trim();
	}

	/**
	 * Replaces all SPACES and COLONS inside the templates with UNDERSCORES and
	 * DASHES, respectively
	 */
	private String fixupTemplateSeparatorsOLD(String name) {
		StringBuffer buffer = new StringBuffer();
		int templateLevel = 0;
		char last = '\u0000';
		for (int i = 0; i < name.length(); ++i) {
			char ch = name.charAt(i);
			if (ch == '<') {
				++templateLevel;
			}
			else if (ch == '>' && templateLevel != 0) {
				--templateLevel;
			}

			if (templateLevel > 0 && ch == ' ') {
				char next = (i + 1) < name.length() ? name.charAt(i + 1) : '\u0000';
				if (isSurroundedByCharacters(last, next)) {
					// separate words with a value so they don't run together; drop the other spaces
					buffer.append('_');
				}
			}
			else if (templateLevel > 0 && ch == ':') {
				buffer.append('-');
			}
			else {
				buffer.append(ch);
			}

			last = ch;
		}
		return buffer.toString().trim();
	}

	private boolean isSurroundedByCharacters(char last, char next) {
		if (last == '\u0000' || next == '\u0000') {
			return false;
		}
		return Character.isLetterOrDigit(last) && Character.isLetterOrDigit(next);
	}

	/**
	 * Searches backward for the specified character
	 * starting at the index.
	 */
	private int backIndexOf(String string, int index, char ch) {
		while (index >= 0) {
			if (string.charAt(index) == ch) {
				return index;
			}
			--index;
		}
		return 0;
	}

	/**
	 * This method separates the parameters as strings.
	 * This is more complicated then one might initially think.
	 * Reason being, you need to take into account nested templates
	 * and function pointers.
	 */
	private List<DemangledDataType> parseParameters(String parameterString) {
		List<String> parameterStrings = tokenizeParameters(parameterString);
		List<DemangledDataType> parameters = convertIntoParameters(parameterStrings);
		return parameters;
	}

	private List<String> tokenizeParameters(String parameterString) {
		List<String> parameters = new ArrayList<>();

		if (parameterString.length() == 0) {
			return parameters;
		}

		// note: this matches the syntax of bob( const(param1, param2)), where for some
		// reason the demangled symbol has const() around the params.  After research, this is seen
		// when demangling functions that have const at the end, such as bob(param1, param2) const;
		Matcher matcher = CONST_FUNCTION_PATTERN.matcher(parameterString);
		if (matcher.matches()) {
			parameterString = matcher.group(1);// group 0 is the entire string
		}
		else {
			matcher = UNNECESSARY_PARENS_PATTERN.matcher(parameterString);
			if (matcher.matches()) {
				parameterString = matcher.group(1);
			}
		}

		if (parameterString.trim().length() == 0) {
			return parameters;
		}

		int templateLevel = 0;
		int functionPointerLevel = 0;
		int startIndex = 0;

		for (int i = 0; i < parameterString.length(); ++i) {
			char ch = parameterString.charAt(i);
			if (ch == ',' && templateLevel == 0 && functionPointerLevel == 0) {
				String ps = parameterString.substring(startIndex, i);
				parameters.add(ps.trim());
				startIndex = i + 1;
			}
			else if (ch == '<') {
				++templateLevel;
			}
			else if (ch == '>') {
				--templateLevel;
			}
			else if (ch == '(') {
				//
				// Move past both sets of parents for function pointers
				// 		e.g., unsigned long (*)(long const &)
				// Also, array pointer/refs
				//  	e.g., short (&)[7]
				//

				// check for array case
				matcher =
					ARRAY_POINTER_REFERENCE_PIECE_PATTERN.matcher(parameterString.substring(i));
				if (matcher.find()) {
					int start = matcher.start();
					if (start == 0) {
						// matched something like: (&)[7]

						// end is the offset *after* the last char matched, so subtract 1, since
						// we want to next process the character after the end of the match and
						// the loop is going to increment i after we continue.
						int end = matcher.end() - 1;
						i += end;
						continue;// skip past the matching array syntax
					}
				}

				matcher = CAST_PATTERN.matcher(parameterString.substring(i));
				if (matcher.find()) {
					int start = matcher.start();
					if (start == 0) {
						// matched something like: (unsigned)4294967295

						// end is the offset *after* the last char matched, so subtract 1, since
						// we want to next process the character after the end of the match and
						// the loop is going to increment i after we continue.
						int end = matcher.end() - 1;
						i += end;
						continue;// skip past the matching cast syntax
					}
				}

				i = getFunctionPointerCloseParen(parameterString, i);
			}
		}
		if (startIndex < parameterString.length()) {
			String ps = parameterString.substring(startIndex, parameterString.length());
			parameters.add(ps.trim());
		}
		return parameters;
	}

	private int getFunctionPointerCloseParen(String parameterString, int currentIndex) {
		int firstCloseParen = parameterString.indexOf(')', currentIndex);
		if (firstCloseParen == -1) {
			throw new RuntimeException(
				"Unable to find closing paren for parameter string: " + parameterString);
		}

		//
		// we wish to move past two sets of parens for function pointers; however, sometimes
		// we have code with only one set of parens; for example:
		//   unsigned long (*)(long const &)
		// or
		//   iterator<boost::function<void ()>
		//
		boolean foundNextStart = false;
		int length = parameterString.length();
		for (int i = currentIndex; i < length; i++) {
			char ch = parameterString.charAt(i);
			if (ch == ')') {
				return i;
			}
			else if (ch == '(') {
				foundNextStart = true;
			}
			else if (ch == ',') {
				if (!foundNextStart) {
					return firstCloseParen;// no new set of parens found
				}
			}
		}

		return firstCloseParen;
	}

	/**
	 * This method converts each parameter string into
	 * actual DemangledDataType objects.
	 */
	private List<DemangledDataType> convertIntoParameters(List<String> parameterStrings) {
		List<DemangledDataType> parameters = new ArrayList<>();

		for (String parameter : parameterStrings) {
			DemangledDataType ddt = parseDataType(parameter);
			parameters.add(ddt);
		}

		return parameters;
	}

	private DemangledDataType parseDataType(String datatype) {
		DemangledDataType ddt = new DemangledDataType((String) null);
		setNameAndNamespace(ddt, datatype);

		int last_i = 0;
		boolean finishedName = false;
		for (int i = 0; i < datatype.length(); ++i) {

			if (i < last_i) {
				Msg.debug(this, "i less than " + last_i); // TODO delete me
			}
			last_i = i;

			char ch = datatype.charAt(i);

			if (!finishedName && isDataTypeNameCharacter(ch)) {
				continue;
			}

			if (!finishedName) {
				finishedName = true;

				if (VAR_ARGS.equals(datatype)) {
					ddt.setVarArgs();
				}
				else {

					Matcher matcher = CAST_PATTERN.matcher(datatype);
					if (matcher.matches()) {
						// special case: template parameter with a cast (just make the datatype
						// be the name of the template parameter, since it will just be a display
						// attribute for the templated type)
						String value = matcher.group(0);// group 0 is the entire match
						return new DemangledDataType(value);
					}

					String name = datatype.substring(0, i).trim();
					setNameAndNamespace(ddt, name);
				}
			}

			if (ch == '<') {//start of template
				int contentStart = i + 1;
				int templateEnd = getTemplateEndIndex(datatype, contentStart);
				if (templateEnd == -1 || templateEnd > datatype.length()) {
					throw new RuntimeException("Did not find ending to template");
				}

				String templateContent = datatype.substring(contentStart, templateEnd);
				DemangledTemplate template = parseTemplate(templateContent);
				ddt.setTemplate(template);
				i = templateEnd;

				if (i < last_i) {
					Msg.debug(this, "\ttemplate end: " + i);
				}
			}
			else if (ch == '(') {// start of function pointer or array ref/pointer
				//
				// function pointer
				// 		e.g., unsigned long (*)(long const &)
				// array pointer/refs
				//  	e.g., short (&)[7]
				//

				// check for array case
				Matcher matcher = ARRAY_POINTER_REFERENCE_PATTERN.matcher(datatype);
				if (matcher.matches()) {
					String name = matcher.group(1);// group 0 is the entire string
					ddt = parseArrayPointerOrReference(datatype, name);
					i = matcher.end();

					if (i < last_i) {
						Msg.debug(this, "\tarray matcher end: " + i);
					}
				}
				else {
					int startParenCount =
						StringUtilities.countOccurrences(datatype.substring(i), '(');
					boolean hasPointerParens = startParenCount == 2;
					if (hasPointerParens) {
						ddt = parseFunctionPointer(datatype);
						int firstParenEnd = datatype.indexOf(')', i + 1);
						int secondParenEnd = datatype.indexOf(')', firstParenEnd + 1);
						if (secondParenEnd == -1) {
							throw new RuntimeException(
								"Did not find ending to closure: " + datatype);
						}
						i = secondParenEnd + 1; // two sets of parens (normal case)

						if (i < last_i) {
							Msg.debug(this, "\tsecond paren end: " + i);
						}
					}
					else {
						ddt = parseFunction(datatype, i);
						int firstParenEnd = datatype.indexOf(')', i + 1);
						if (firstParenEnd == -1) {
							throw new RuntimeException(
								"Did not find ending to closure: " + datatype);
						}
						i = firstParenEnd + 1;// two sets of parens (normal case)

						if (i < last_i) {
							Msg.debug(this, "\tfirst paren end: " + i);
						}
					}
				}
			}
			else if (ch == '*') {
				ddt.incrementPointerLevels();
			}
			else if (ch == '&') {
				if (!ddt.isReference()) {
					ddt.setReference();
				}
				else {
					ddt.incrementPointerLevels();
				}
			}
			else if (ch == '[') { // should we consume closing ']'
				ddt.setArray(ddt.getArrayDimensions() + 1);
			}

			String substr = datatype.substring(i);

			if (substr.startsWith("const")) {
				ddt.setConst();
				i += 4;
			}
			else if (substr.startsWith("struct")) {
				ddt.setStruct();
				i += 5;
			}
			else if (substr.startsWith("class")) {
				ddt.setClass();
				i += 4;
			}
			else if (substr.startsWith("enum")) {
				ddt.setEnum();
				i += 3;
			}
			else if (ddt.getName().equals("long")) {
				if (substr.startsWith("long")) {
					ddt.setName(DemangledDataType.LONG_LONG);
					i += 3;
				}
				else if (substr.startsWith("double")) {
					ddt.setName(DemangledDataType.LONG_DOUBLE);
					i += 5;
				}
			}
			// unsigned can also mean unsigned long, int
			else if (ddt.getName().equals("unsigned")) {
				ddt.setUnsigned();
				if (substr.startsWith("long")) {
					ddt.setName(DemangledDataType.LONG);
					i += 3;
				}
				else if (substr.startsWith("int")) {
					ddt.setName(DemangledDataType.INT);
					i += 2;
				}
				else if (substr.startsWith("short")) {
					ddt.setName(DemangledDataType.SHORT);
					i += 4;
				}
				else if (substr.startsWith("char")) {
					ddt.setName(DemangledDataType.CHAR);
					i += 3;
				}
			}
		}
		return ddt;
	}

	private boolean isDataTypeNameCharacter(char ch) {

		/*
			Note: really, this should just be checking a list of known disallowed characters, 
				  which is something like:
				  
				  <,>,(,),&,*,[,]
		
		 		  It seems like the current code below is unnecessarily restrictive
		 */

		//@formatter:off
		return Character.isLetter(ch) || 
			   Character.isDigit(ch) || 
			   ch == ':' || 
			   ch == '_' ||
			   ch == '$';
		//@formatter:on
	}

	// scan to last part of template
	private int getTemplateEndIndex(String datatype, int start) {
		int endIndex = start;
		int depth = 1;
		while (endIndex < datatype.length()) {
			char tempCh = datatype.charAt(endIndex);
			if (tempCh == '>') {
				depth--;
				if (depth == 0) {
					break;
				}
			}
			if (tempCh == '<') {
				depth++;
			}
			endIndex++;
		}
		return endIndex;
	}

	private void setNameAndNamespace(DemangledDataType ddt, String name) {
		SymbolPath path = new SymbolPath(name);
		List<String> names = path.asList();

		DemangledType namespace = null;
		if (names.size() > 1) {
			namespace = DemanglerUtil.convertToNamespaces(names.subList(0, names.size() - 1));
		}

		String datatypeName = names.get(names.size() - 1);

		ddt.setName(datatypeName);
		ddt.setNamespace(namespace);
	}

	private void setNameAndNamespace(DemangledObject object, String name) {

		SymbolPath path = new SymbolPath(name);
		List<String> names = path.asList();

		DemangledType namespace = null;
		if (names.size() > 1) {
			namespace = DemanglerUtil.convertToNamespaces(names.subList(0, names.size() - 1));
		}

		String objectName = names.get(names.size() - 1);

		object.setName(objectName);
		object.setNamespace(namespace);
	}

	private void setNamespace(DemangledObject object, String name) {

		SymbolPath path = new SymbolPath(name);
		List<String> names = path.asList();
		object.setNamespace(DemanglerUtil.convertToNamespaces(names));
	}

	private DemangledTemplate parseTemplate(String templateStr) {
		List<DemangledDataType> parameters = parseParameters(templateStr);
		DemangledTemplate template = new DemangledTemplate();
		for (DemangledDataType parameter : parameters) {
			template.addParameter(parameter);
		}
		return template;
	}

	private DemangledDataType parseArrayPointerOrReference(String datatype, String name) {
		// int (*)[8]
		// char (&)[7]

		DemangledDataType ddt = new DemangledDataType(name);
		Matcher matcher = ARRAY_POINTER_REFERENCE_PATTERN.matcher(datatype);
		matcher.find();
		String type = matcher.group(3);
		if (type.equals("*")) {
			ddt.incrementPointerLevels();
		}
		else if (type.equals("&")) {
			ddt.setReference();
		}
		else {
			throw new RuntimeException("Unexpected charater inside of parens: " + type);
		}

		String arraySubscripts = matcher.group(4);
		int n = StringUtilities.countOccurrences(arraySubscripts, '[');
		ddt.setArray(n);

		return ddt;
	}

	private DemangledDataType parseFunctionPointer(String functionPointerString) {
		//unsigned long (*)(long const &)

		int parenStart = functionPointerString.indexOf('(');
		int parenEnd = functionPointerString.indexOf(')');

		String returnType = functionPointerString.substring(0, parenStart).trim();

		int paramStart = functionPointerString.indexOf('(', parenEnd + 1);
		int paramEnd = functionPointerString.lastIndexOf(')');
		String parameterStr = functionPointerString.substring(paramStart + 1, paramEnd);
		List<DemangledDataType> parameters = parseParameters(parameterStr);

		DemangledFunctionPointer dfp = new DemangledFunctionPointer();
		dfp.setReturnType(parseDataType(returnType));
		for (DemangledDataType parameter : parameters) {
			dfp.addParameter(parameter);
		}

		return dfp;
	}

	private DemangledDataType parseFunction(String functionString, int offset) {
		//unsigned long (long const &)

		int parenStart = functionString.indexOf('(', offset);
		int parenEnd = functionString.indexOf(')', parenStart + 1);

		String returnType = functionString.substring(0, parenStart).trim();

		int paramStart = parenStart;
		int paramEnd = parenEnd;
		String parameterStr = functionString.substring(paramStart + 1, paramEnd);
		List<DemangledDataType> parameters = parseParameters(parameterStr);

		DemangledFunctionPointer dfp = new DemangledFunctionPointer();
		dfp.setReturnType(parseDataType(returnType));
		for (DemangledDataType parameter : parameters) {
			dfp.addParameter(parameter);
		}

		dfp.setDisplayFunctionPointerParens(false);
		return dfp;
	}

	private DemangledObject parseVariable(String demangled) {

		/*
		 	Examples:
		 	
		 		NS1::Function<>()::StructureName::StructureConstructor()
		 	
		 */

		String nameString = fixupInternalSeparators(demangled).trim();
		boolean inNamespace = nameString.contains(NAMESPACE_DELIMITER);
		if (!inNamespace) {
			int nameSeparator = nameString.lastIndexOf(' ');
			if (nameSeparator != -1) {
				nameString = nameString.substring(0, nameSeparator);
			}
		}

		DemangledVariable variable = new DemangledVariable((String) null);
		setNameAndNamespace(variable, nameString);
		return variable;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private abstract class SpecialPrefixHandler {

		protected String demangled;
		protected String prefix;
		protected String name;
		protected String parent;

		abstract String getParent();

		abstract DemangledObject build(Demangled namespace);
	}

	private class TypeInfoNameHandler extends SpecialPrefixHandler {

		TypeInfoNameHandler(String demangled, String prefix) {
			this.demangled = demangled;
			this.prefix = prefix;
		}

		@Override
		String getParent() {
			String classname = demangled.substring(prefix.length()).trim();
			parent = classname;
			return parent;
		}

		@Override
		DemangledObject build(Demangled namespace) {
			DemangledString demangledString =
				new DemangledString("typeinfo-name", parent, -1/*unknown length*/, false);
			demangledString.setSpecialPrefix("typeinfo name");
			demangledString.setUtilDemangled(demangled);
			setNamespace(demangledString, parent);
			return demangledString;
		}
	}

	private class AddressTableHandler extends SpecialPrefixHandler {

		AddressTableHandler(String demangled, String prefix) {
			this.demangled = demangled;
			this.prefix = prefix;
		}

		@Override
		String getParent() {

			/*
			 Samples:
			 	 prefix: construction vtable for 
			 	 name:   construction-vtable
			 	 
			 	 prefix: vtable for 
			 	 name:   vtable
			 
			 	 prefix: typeinfo name for 
			 	 name:   typeinfo-name
			 	 
			 	 prefix: covariant return thunk
			 	 name:   covariant-return
			*/

			// TODO can we replace the below with something simpler?
			int pos = prefix.trim().lastIndexOf(' ');
			name = prefix.substring(0, pos).replace(' ', '-');
			parent = demangled.substring(prefix.length()).trim();
			return parent;
		}

		@Override
		DemangledObject build(Demangled demangledParent) {
			Demangled namespace = demangledParent;
			DemangledAddressTable addressTable = new DemangledAddressTable(name, true);
			addressTable.setNamespace(namespace);
			return addressTable;
		}
	}

	private class ConstructionVTableHandler extends AddressTableHandler {

		ConstructionVTableHandler(String demangled, String prefix) {
			super(demangled, prefix);

			Matcher matcher = ENDS_WITH_DIGITS_PATTERN.matcher(demangled);
			if (matcher.matches()) {
				// ends with a number, strip it off
				this.demangled = matcher.group(1);
			}
		}
	}

	private abstract class OperatorHandler {

		protected Matcher matcher;

		abstract boolean matches(String s);

		abstract DemangledObject build();
	}

	private class OverloadOperatorHandler extends OperatorHandler {

		@Override
		boolean matches(String demangled) {
			matcher = OVERLOAD_OPERATOR_PATTERN.matcher(demangled);
			return matcher.matches();
		}

		@Override
		DemangledObject build() {

			//
			// An example to follow along with:
			//
			// 'overloaded operator' syntax is:
			// [return_type] operator<operator_chars>[templates](parameters)
			//
			// Namespace::Class::operator Namespace::Type()
			//
			// NS1::operator<(NS1::Coordinate const &,NS1::Coordinate const &)
			//

			// prefix: return_type operator operator_chars[templates]
			// 		   (everything before the parameters)
			String operatorPrefix = matcher.group(1);
			String operatorChars = matcher.group(2);
			String parametersText = matcher.group(3);
			String trailing = matcher.group(4);

			int index = operatorPrefix.indexOf("operator");

			/*
			 	TODO
			 	TODO  this is similar to the main algo that replaces template spaces before
			 		  scanning for the name space; use that
			 	TODO 
			 	
			 */

			String returnTypeText = "undefined";
			String operatorName = operatorPrefix;
			GroupScanner scanner = new GroupScanner(operatorPrefix, index);
			scanner.setIgnoreTemplates(true); // TODO turn on by default?
			int splitSpace = scanner.previous(' ');
			if (splitSpace != -1) {
				returnTypeText = operatorPrefix.substring(0, splitSpace);
				operatorName = operatorPrefix.substring(splitSpace + 1);
			}

			DemangledDataType returnType = new DemangledDataType((String) null);

			returnTypeText = fixupInternalSeparators(returnTypeText);
			// TODO be better at detecting attributes; find examples
			if (returnTypeText.endsWith("&")) {
				returnTypeText = returnTypeText.substring(0, returnTypeText.length() - 1);
				returnType.setReference();
			}
			setNameAndNamespace(returnType, returnTypeText);

			DemangledMethod method = new DemangledMethod((String) null);
			method.setOverloadedOperator(true);
			method.setReturnType(returnType);

			operatorName = fixupInternalSeparators(operatorName);
			setNameAndNamespace(method, operatorName);

			List<DemangledDataType> parameters = parseParameters(parametersText);
			for (DemangledDataType parameter : parameters) {
				method.addParameter(parameter);
			}

			// TODO do we need to specify a custom signature?
			// method.setSignature(operatorText + " " + operatorName);

			return method;
		}
	}

	private class GroupScanner {

		private String text;
		private boolean ignoreParens;
		private boolean ignoreTemplates;

		private int length;
		private int index;
		private int ignoreCount = 0; // templates and parameters

		GroupScanner(String text) {
			this.text = text;
			this.length = text.length();
		}

		GroupScanner(String text, int index) {
			this.text = text;
			this.length = text.length();
			this.index = index;
		}

		void setIgnoreTemplates(boolean b) {
			this.ignoreTemplates = b;
		}

		void setIgnoreParens(boolean b) {
			this.ignoreParens = b;
		}

		char peek() {
			return text.charAt(index);
		}

		int next(char toFind) {
			for (; index < length; index++) {
				char c = text.charAt(index);

				if (ignoreTemplates && c == '<') {
					ignoreCount++;
					continue;
				}

				if (ignoreParens && c == '(') {
					ignoreCount++;
					continue;
				}

				if (ignoreTemplates && c == '>') {
					ignoreCount--;
					continue;
				}

				if (ignoreParens && c == ')') {
					ignoreCount--;
					continue;
				}

				if (ignoreCount != 0) {
					continue;
				}

				if (c == toFind) {
					return index++;
				}
			}

			return -1;
		}

		int previous(char toFind) {
			for (; index >= 0; index--) {
				char c = text.charAt(index);

				if (ignoreTemplates && c == '>') {
					ignoreCount++;
					continue;
				}

				if (ignoreParens && c == ')') {
					ignoreCount++;
					continue;
				}

				if (ignoreTemplates && c == '<') {
					ignoreCount--;
					continue;
				}

				if (ignoreParens && c == '(') {
					ignoreCount--;
					continue;
				}

				if (ignoreCount != 0) {
					continue;
				}

				if (c == toFind) {
					return index--;
				}
			}

			return -1;
		}
	}

	private class ConversionOperatorHandler extends OperatorHandler {

		@Override
		boolean matches(String demangled) {
			matcher = CONVERSION_OPERATOR_PATTERN.matcher(demangled);
			return matcher.matches();
		}

		@Override
		DemangledObject build() {
			return parseConversionOperator(matcher);
		}
	}

	private class NewOrDeleteOperatorHandler extends OperatorHandler {

		@Override
		boolean matches(String demangler) {
			matcher = NEW_DELETE_OPERATOR_PATTERN.matcher(demangler);
			return matcher.matches();
		}

		@Override
		DemangledObject build() {
			return parseNewOrDeleteOperator(matcher);
		}
	}

	private class ParameterLocator {
		int paramStart = -1;
		int paramEnd = -1;

		ParameterLocator(String text) {
			paramEnd = text.lastIndexOf(')');
			if (paramEnd < 0) {
				return;
			}
			if (isContainedWithinNamespace(text)) {
				// ignore param list associated with namespace specification
				paramEnd = -1;
				return;
			}
			paramStart = findParameterStart(text, paramEnd);
			int templateEnd = findInitialTemplateEndPosition(text);
			int templateStart = -1;
			if (templateEnd != -1) {
				templateStart = findInitialTemplateStartPosition(text, templateEnd);
			}
			if (paramStart > templateStart && paramStart < templateEnd) {
				// ignore parentheses inside of templates (they are cast operators)
				paramStart = -1;
				paramEnd = -1;
			}
		}

		private boolean isContainedWithinNamespace(String text) {
			return (paramEnd < (text.length() - 1)) && (':' == text.charAt(paramEnd + 1));
		}

		int getParamStart() {
			return paramStart;
		}

		int getParamEnd() {
			return paramEnd;
		}

		boolean hasParameters() {
			return paramStart != -1 && paramEnd != -1;
		}

		private int findParameterStart(String demangled, int end) {
			int templateLevel = 0;
			int functionPointerLevel = 0;
			for (int i = end - 1; i >= 0; --i) {
				char ch = demangled.charAt(i);
				if (ch == '(' && templateLevel == 0 && functionPointerLevel == 0) {
					return i;
				}
				else if (ch == '>') {
					++templateLevel;
				}
				else if (ch == '<') {
					--templateLevel;
				}
				else if (ch == ')') {
					++functionPointerLevel;
				}
				else if (ch == '(') {
					--functionPointerLevel;
				}
			}
			return -1;
		}

		private int findInitialTemplateEndPosition(String string) {

			boolean seenTemplate = false;
			int templateLevel = 0;
			char[] chars = string.toCharArray();
			for (int i = 0; i < chars.length; i++) {
				switch (chars[i]) {
					case '<':
						templateLevel++;
						seenTemplate = true;
						break;
					case '>':
						templateLevel--;
						break;
				}

				if (seenTemplate && templateLevel == 0) {
					return i;
				}
			}

			return -1;
		}

		private int findInitialTemplateStartPosition(String string, int templateEnd) {
			// note: we are moving backwards!
			int templateLevel = 1;
			char[] chars = string.toCharArray();
			for (int i = templateEnd - 1; i >= 0; i--) {
				switch (chars[i]) {
					case '<':
						templateLevel--;
						break;
					case '>':
						templateLevel++;
						break;
				}

				if (templateLevel == 0) {
					return i;// found our opening tag
				}
			}

			return -1;
		}
	}

	private class LambdaName {

		private String fullText;
		private String params;
		private String trailing;

		LambdaName(String fullText, String params, String trailing) {
			this.fullText = fullText;
			this.params = params;
			this.trailing = trailing;
		}

		String getNameWithId() {
			return LAMBDA + trailing;
		}

		String getFullText() {
			return fullText;
		}

		String getParams() {
			return params;
		}

		String getTrailing() {
			return trailing;
		}

	}
}
