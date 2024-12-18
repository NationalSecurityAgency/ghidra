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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.Icon;

import generic.theme.GIcon;
import generic.theme.Gui;
import ghidra.dbg.util.ShellUtils;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.LaunchParameter;
import ghidra.framework.Application;
import ghidra.framework.plugintool.AutoConfigState.PathIsDir;
import ghidra.framework.plugintool.AutoConfigState.PathIsFile;
import ghidra.util.*;

/**
 * A parser for reading attributes from a script header
 */
public abstract class ScriptAttributesParser {
	public static final String ENV_GHIDRA_HOME = "GHIDRA_HOME";
	public static final String ENV_GHIDRA_TRACE_RMI_ADDR = "GHIDRA_TRACE_RMI_ADDR";
	public static final String ENV_GHIDRA_TRACE_RMI_HOST = "GHIDRA_TRACE_RMI_HOST";
	public static final String ENV_GHIDRA_TRACE_RMI_PORT = "GHIDRA_TRACE_RMI_PORT";

	public static final String AT_ARG = "@arg";
	public static final String AT_ARGS = "@args";
	public static final String AT_DESC = "@desc";
	public static final String AT_ENUM = "@enum";
	public static final String AT_ENV = "@env";
	public static final String AT_HELP = "@help";
	public static final String AT_ICON = "@icon";
	public static final String AT_IMAGE_OPT = "@image-opt";
	public static final String AT_MENU_GROUP = "@menu-group";
	public static final String AT_MENU_ORDER = "@menu-order";
	public static final String AT_MENU_PATH = "@menu-path";
	public static final String AT_TITLE = "@title";
	public static final String AT_TIMEOUT = "@timeout";
	public static final String AT_TTY = "@tty";

	public static final String KEY_ARGS = "args";
	public static final String PREFIX_ARG = "arg:";
	public static final String PREFIX_ENV = "env:";

	public static final String MSGPAT_DUPLICATE_TAG = "%s: Duplicate %s";
	public static final String MSGPAT_INVALID_ARG_SYNTAX =
		"%s: Invalid %s syntax. Use :type \"Display\" \"Tool Tip\"";
	public static final String MSGPAT_INVALID_ARGS_SYNTAX =
		"%s: Invalid %s syntax. Use \"Display\" \"Tool Tip\"";
	public static final String MSGPAT_INVALID_ENUM_SYNTAX =
		"%s: Invalid %s syntax. Use NAME:type Choice1 [ChoiceN...]";
	public static final String MSGPAT_INVALID_ENV_SYNTAX =
		"%s: Invalid %s syntax. Use NAME:type=default \"Display\" \"Tool Tip\"";
	public static final String MSGPAT_INVALID_HELP_SYNTAX =
		"%s: Invalid %s syntax. Use Topic#anchor";
	public static final String MSGPAT_INVALID_TIMEOUT_SYNTAX = "" +
		"%s: Invalid %s syntax. Use [milliseconds]";
	public static final String MSGPAT_INVALID_TTY_BAD_VAL =
		"%s: In %s: Parameter '%s' has type %s, but '%s' cannot be parsed as such";
	public static final String MSGPAT_INVALID_TTY_NO_PARAM =
		"%s: In %s: No such parameter '%s'";
	public static final String MSGPAT_INVALID_TTY_NOT_BOOL =
		"%s: In %s: Parameter '%s' must have bool type";
	public static final String MSGPAT_INVALID_TTY_SYNTAX =
		"%s: Invalid %s syntax. Use TTY_TARGET [if env:OPT [== VAL]]";

	public static class ParseException extends Exception {
		private Location loc;

		public ParseException(Location loc, String message) {
			super(message);
			this.loc = loc;
		}

		public Location getLocation() {
			return loc;
		}
	}

	protected record Location(String fileName, int lineNo) {
		@Override
		public String toString() {
			return "%s:%d".formatted(fileName, lineNo);
		}
	}

	protected interface OptType<T> extends ValStr.Decoder<T> {
		static OptType<?> parse(Location loc, String typeName, Map<String, UserType<?>> userEnums)
				throws ParseException {
			OptType<?> type = BaseType.parseNoErr(typeName);
			if (type == null) {
				type = userEnums.get(typeName);
			}
			if (type == null) { // still
				throw new ParseException(loc, "%s: Invalid type %s".formatted(loc, typeName));
			}
			return type;
		}

		default TypeAndDefault<T> withCastDefault(ValStr<Object> defaultValue) {
			return new TypeAndDefault<>(this, ValStr.cast(cls(), defaultValue));
		}

		Class<T> cls();

		default T decode(Location loc, String str) throws ParseException {
			try {
				return decode(str);
			}
			catch (Exception e) {
				throw new ParseException(loc, "%s: %s".formatted(loc, e.getMessage()));
			}
		}

		LaunchParameter<T> createParameter(String name, String display, String description,
				boolean required, ValStr<T> defaultValue);
	}

	protected interface BaseType<T> extends OptType<T> {
		public static BaseType<?> parseNoErr(String typeName) {
			return switch (typeName) {
				case "str" -> BaseType.STRING;
				case "int" -> BaseType.INT;
				case "bool" -> BaseType.BOOL;
				case "path" -> BaseType.PATH;
				case "dir" -> BaseType.DIR;
				case "file" -> BaseType.FILE;
				default -> null;
			};
		}

		public static BaseType<?> parse(Location loc, String typeName) throws ParseException {
			BaseType<?> type = parseNoErr(typeName);
			if (type == null) {
				throw new ParseException(loc, "%s: Invalid base type %s".formatted(loc, typeName));
			}
			return type;
		}

		public static final BaseType<String> STRING = new BaseType<>() {
			@Override
			public Class<String> cls() {
				return String.class;
			}

			@Override
			public String decode(String str) {
				return str;
			}
		};

		public static final BaseType<BigInteger> INT = new BaseType<>() {
			@Override
			public Class<BigInteger> cls() {
				return BigInteger.class;
			}

			@Override
			public BigInteger decode(String str) {
				try {
					return NumericUtilities.decodeBigInteger(str);
				}
				catch (NumberFormatException e) {
					throw new IllegalArgumentException(
						"Invalid int %s. Prefixes 0x, 0b, and 0 (octal) are allowed."
								.formatted(str));
				}
			}
		};

		public static final BaseType<Boolean> BOOL = new BaseType<>() {
			@Override
			public Class<Boolean> cls() {
				return Boolean.class;
			}

			@Override
			public Boolean decode(String str) {
				Boolean result = switch (str.trim().toLowerCase()) {
					case "true" -> true;
					case "false" -> false;
					default -> null;
				};
				if (result == null) {
					throw new IllegalArgumentException(
						"Invalid bool for %s: %s. Only true or false is allowed."
								.formatted(AT_ENV, str));
				}
				return result;
			}
		};

		public static final BaseType<Path> PATH = new BaseType<>() {
			@Override
			public Class<Path> cls() {
				return Path.class;
			}

			@Override
			public Path decode(String str) {
				return Paths.get(str);
			}
		};

		public static final BaseType<PathIsDir> DIR = new BaseType<>() {
			@Override
			public Class<PathIsDir> cls() {
				return PathIsDir.class;
			}

			@Override
			public PathIsDir decode(String str) {
				return new PathIsDir(Paths.get(str));
			}
		};

		public static final BaseType<PathIsFile> FILE = new BaseType<>() {
			@Override
			public Class<PathIsFile> cls() {
				return PathIsFile.class;
			}

			@Override
			public PathIsFile decode(String str) {
				return new PathIsFile(Paths.get(str));
			}
		};

		default UserType<T> withCastChoices(List<?> choices) {
			return new UserType<>(this, choices.stream().map(cls()::cast).toList());
		}

		default UserType<T> withChoices(List<T> choices) {
			return new UserType<>(this, choices);
		}

		@Override
		default LaunchParameter<T> createParameter(String name, String display, String description,
				boolean required, ValStr<T> defaultValue) {
			return LaunchParameter.create(cls(), name, display, description, required, defaultValue,
				this);
		}
	}

	protected record UserType<T>(BaseType<T> base, List<T> choices) implements OptType<T> {
		@Override
		public Class<T> cls() {
			return base.cls();
		}

		@Override
		public T decode(String str) {
			return base.decode(str);
		}

		@Override
		public LaunchParameter<T> createParameter(String name, String display, String description,
				boolean required, ValStr<T> defaultValue) {
			return LaunchParameter.choices(cls(), name, display, description, choices,
				defaultValue);
		}
	}

	protected record TypeAndDefault<T>(OptType<T> type, ValStr<T> defaultValue) {
		public static TypeAndDefault<?> parse(Location loc, String typeName, String defaultString,
				Map<String, UserType<?>> userEnums) throws ParseException {
			OptType<?> tac = OptType.parse(loc, typeName, userEnums);
			Object value = tac.decode(loc, defaultString);
			return tac.withCastDefault(new ValStr<>(value, defaultString));
		}

		public LaunchParameter<T> createParameter(String name, String display, String description,
				boolean required) {
			return type.createParameter(name, display, description, required, defaultValue);
		}
	}

	public interface TtyCondition {
		boolean isActive(Map<String, ValStr<?>> args);
	}

	enum ConstTtyCondition implements TtyCondition {
		ALWAYS {
			@Override
			public boolean isActive(Map<String, ValStr<?>> args) {
				return true;
			}
		},
	}

	record EqualsTtyCondition(LaunchParameter<?> param, Object value) implements TtyCondition {
		@Override
		public boolean isActive(Map<String, ValStr<?>> args) {
			ValStr<?> valStr = param.get(args);
			return Objects.equals(valStr == null ? null : valStr.val(), value);
		}
	}

	record BoolTtyCondition(LaunchParameter<Boolean> param) implements TtyCondition {
		@Override
		public boolean isActive(Map<String, ValStr<?>> args) {
			ValStr<Boolean> valStr = param.get(args);
			return valStr != null && valStr.val();
		}
	}

	protected static String addrToString(InetAddress address) {
		if (address.isAnyLocalAddress()) {
			return "127.0.0.1"; // Can't connect to 0.0.0.0 as such. Choose localhost.
		}
		return address.getHostAddress();
	}

	protected static String sockToString(SocketAddress address) {
		if (address instanceof InetSocketAddress tcp) {
			return addrToString(tcp.getAddress()) + ":" + tcp.getPort();
		}
		throw new AssertionError("Unhandled address type " + address);
	}

	public record ScriptAttributes(String title, String description, List<String> menuPath,
			String menuGroup, String menuOrder, Icon icon, HelpLocation helpLocation,
			Map<String, LaunchParameter<?>> parameters, Map<String, TtyCondition> extraTtys,
			int timeoutMillis, LaunchParameter<?> imageOpt) {}

	/**
	 * Convert an arguments map into a command line and environment variables
	 * 
	 * @param commandLine a mutable list to add command line parameters into
	 * @param env a mutable map to place environment variables into. This should likely be
	 *            initialized to {@link System#getenv()} so that Ghidra's environment is inherited
	 *            by the script's process.
	 * @param script the script file
	 * @param parameters the descriptions of the parameters
	 * @param args the arguments to process
	 * @param address the address of the listening TraceRmi socket
	 */
	public static void processArguments(List<String> commandLine, Map<String, String> env,
			File script, Map<String, LaunchParameter<?>> parameters, Map<String, ValStr<?>> args,
			SocketAddress address) {

		commandLine.add(script.getAbsolutePath());
		env.put(ENV_GHIDRA_HOME, Application.getInstallationDirectory().getAbsolutePath());
		if (address != null) {
			env.put(ENV_GHIDRA_TRACE_RMI_ADDR, sockToString(address));
			if (address instanceof InetSocketAddress tcp) {
				env.put(ENV_GHIDRA_TRACE_RMI_HOST, tcp.getAddress().getHostAddress());
				env.put(ENV_GHIDRA_TRACE_RMI_PORT, Integer.toString(tcp.getPort()));
			}
		}

		LaunchParameter<?> param;
		for (int i = 1; (param = parameters.get("arg:" + i)) != null; i++) {
			// Don't use ValStr.str here. I'd like the script's input normalized
			commandLine.add(param.get(args).normStr());
		}

		param = parameters.get("args");
		if (param != null) {
			commandLine.addAll(ShellUtils.parseArgs(param.get(args).str()));
		}

		for (Entry<String, LaunchParameter<?>> ent : parameters.entrySet()) {
			String key = ent.getKey();
			if (key.startsWith(PREFIX_ENV)) {
				String varName = key.substring(PREFIX_ENV.length());
				ValStr<?> val = ent.getValue().get(args);
				env.put(varName, ValStr.normStr(val));
			}
		}
	}

	private int argc;
	private String title;
	private StringBuilder description;
	private String iconId;
	private HelpLocation helpLocation;
	private String menuGroup;
	private String menuOrder;
	private List<String> menuPath;
	private final Map<String, UserType<?>> userTypes = new HashMap<>();
	private final Map<String, LaunchParameter<?>> parameters = new LinkedHashMap<>();
	private final Map<String, TtyCondition> extraTtys = new LinkedHashMap<>();
	private int timeoutMillis = AbstractTraceRmiLaunchOffer.DEFAULT_TIMEOUT_MILLIS;
	private String imageOptKey;

	/**
	 * Check if a line should just be ignored, e.g., blank lines, or the "shebang" line on UNIX.
	 * 
	 * @param lineNo the line number, counting 1 up
	 * @param line the full line, excluding the new-line characters
	 * @return true to ignore, false to parse
	 */
	protected abstract boolean ignoreLine(int lineNo, String line);

	/**
	 * Check if a line is a comment and extract just the comment
	 * 
	 * <p>
	 * If null is returned, the parser assumes the attributes header is ended
	 * 
	 * @param line the full line, excluding the new-line characters
	 * @return the comment, or null if the line is not a comment
	 */
	protected abstract String removeDelimiter(String line);

	/**
	 * Parse the header from the give input stream
	 * 
	 * @param stream the stream from of the input stream file
	 * @param scriptName the name of the script file
	 * @return the parsed attributes
	 * @throws IOException if there was an issue reading the stream
	 */
	public ScriptAttributes parseStream(InputStream stream, String scriptName) throws IOException {
		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(stream))) {
			String line;
			for (int lineNo = 1; (line = reader.readLine()) != null; lineNo++) {
				if (ignoreLine(lineNo, line)) {
					continue;
				}
				String comment = removeDelimiter(line);
				if (comment == null) {
					break;
				}
				parseComment(new Location(scriptName, lineNo), comment);
			}
			return validate(scriptName);
		}
	}

	/**
	 * Parse the header of the given script file
	 * 
	 * @param script the file
	 * @return the parsed attributes
	 * @throws FileNotFoundException if the script file could not be found
	 */
	public ScriptAttributes parseFile(File script) throws FileNotFoundException {
		try {
			return parseStream(new FileInputStream(script), script.getName());
		}
		catch (FileNotFoundException e) {
			// Avoid capture by IOException
			throw e;
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Process a line in the metadata comment block
	 * 
	 * @param loc the location, for error reporting
	 * @param comment the comment, excluding any comment delimiters
	 */
	public void parseComment(Location loc, String comment) {
		if (comment.isBlank()) {
			return;
		}
		String[] parts = comment.split("\\s+", 2);
		if (!parts[0].startsWith("@")) {
			return;
		}
		if (parts.length == 1) {
			parseUnrecognized(loc, comment);
		}
		else {
			switch (parts[0].trim()) {
				case AT_ARG -> parseArg(loc, parts[1], ++argc);
				case AT_ARGS -> parseArgs(loc, parts[1]);
				case AT_DESC -> parseDesc(loc, parts[1]);
				case AT_ENUM -> parseEnum(loc, parts[1]);
				case AT_ENV -> parseEnv(loc, parts[1]);
				case AT_HELP -> parseHelp(loc, parts[1]);
				case AT_ICON -> parseIcon(loc, parts[1]);
				case AT_IMAGE_OPT -> parseImageOpt(loc, parts[1]);
				case AT_MENU_GROUP -> parseMenuGroup(loc, parts[1]);
				case AT_MENU_ORDER -> parseMenuOrder(loc, parts[1]);
				case AT_MENU_PATH -> parseMenuPath(loc, parts[1]);
				case AT_TIMEOUT -> parseTimeout(loc, parts[1]);
				case AT_TITLE -> parseTitle(loc, parts[1]);
				case AT_TTY -> parseTty(loc, parts[1]);
				default -> parseUnrecognized(loc, comment);
			}
		}
	}

	protected void parseArg(Location loc, String str, int argNum) {
		List<String> parts = ShellUtils.parseArgs(str);
		if (parts.size() != 3) {
			reportError(MSGPAT_INVALID_ARG_SYNTAX.formatted(loc, AT_ARG));
			return;
		}
		String colonType = parts.get(0).trim();
		if (!colonType.startsWith(":")) {
			reportError(MSGPAT_INVALID_ARG_SYNTAX.formatted(loc, AT_ARG));
			return;
		}
		OptType<?> type;
		boolean required = colonType.endsWith("!");
		int endType = required ? colonType.length() - 1 : colonType.length();
		try {
			type = OptType.parse(loc, colonType.substring(1, endType), userTypes);
			String name = PREFIX_ARG + argNum;
			parameters.put(name, type.createParameter(name, parts.get(1), parts.get(2), required,
				new ValStr<>(null, "")));
		}
		catch (ParseException e) {
			reportError(e.getMessage());
		}
	}

	protected void parseArgs(Location loc, String str) {
		List<String> parts = ShellUtils.parseArgs(str);
		if (parts.size() != 2) {
			reportError(MSGPAT_INVALID_ARGS_SYNTAX.formatted(loc, AT_ARGS));
			return;
		}

		LaunchParameter<String> parameter = BaseType.STRING.createParameter(
			"args", parts.get(0), parts.get(1), false, ValStr.str(""));
		if (parameters.put(KEY_ARGS, parameter) != null) {
			reportWarning("%s: Duplicate %s. Replaced".formatted(loc, AT_ARGS));
		}
	}

	protected void parseDesc(Location loc, String str) {
		if (description == null) {
			description = new StringBuilder();
		}
		description.append(str);
		description.append("\n");
	}

	protected <T> UserType<T> parseEnumChoices(Location loc, BaseType<T> baseType,
			List<String> choiceParts) {
		List<T> choices = new ArrayList<>();
		boolean err = false;
		for (String s : choiceParts) {
			try {
				choices.add(baseType.decode(loc, s));
			}
			catch (ParseException e) {
				reportError(e.getMessage());
			}
		}
		if (err) {
			return null;
		}
		return baseType.withChoices(choices);
	}

	protected void parseEnum(Location loc, String str) {
		List<String> parts = ShellUtils.parseArgs(str);
		if (parts.size() < 2) {
			reportError(MSGPAT_INVALID_ENUM_SYNTAX.formatted(loc, AT_ENUM));
			return;
		}
		String[] nameParts = parts.get(0).split(":", 2);
		if (nameParts.length != 2) {
			reportError(MSGPAT_INVALID_ENUM_SYNTAX.formatted(loc, AT_ENUM));
			return;
		}
		String name = nameParts[0].trim();
		BaseType<?> baseType;
		try {
			baseType = BaseType.parse(loc, nameParts[1]);
		}
		catch (ParseException e) {
			reportError(e.getMessage());
			return;
		}
		UserType<?> userType = parseEnumChoices(loc, baseType, parts.subList(1, parts.size()));
		if (userType == null) {
			return; // errors already reported
		}
		if (userTypes.put(name, userType) != null) {
			reportWarning("%s: Duplicate %s %s. Replaced.".formatted(loc, AT_ENUM, name));
		}
	}

	protected void parseEnv(Location loc, String str) {
		List<String> parts = ShellUtils.parseArgs(str);
		if (parts.size() != 3) {
			reportError(MSGPAT_INVALID_ENV_SYNTAX.formatted(loc, AT_ENV));
			return;
		}
		String[] nameParts = parts.get(0).split(":", 2);
		if (nameParts.length != 2) {
			reportError(MSGPAT_INVALID_ENV_SYNTAX.formatted(loc, AT_ENV));
			return;
		}
		String trimmed = nameParts[0].trim();
		String name = PREFIX_ENV + trimmed;
		String[] tadParts = nameParts[1].split("=", 2);
		if (tadParts.length != 2) {
			reportError(MSGPAT_INVALID_ENV_SYNTAX.formatted(loc, AT_ENV));
			return;
		}
		String typePart = tadParts[0].trim();
		boolean required = typePart.endsWith("!");
		int endType = required ? typePart.length() - 1 : typePart.length();
		try {
			TypeAndDefault<?> tad = TypeAndDefault.parse(loc, typePart.substring(0, endType),
				tadParts[1].trim(), userTypes);
			LaunchParameter<?> param =
				tad.createParameter(name, parts.get(1), parts.get(2), required);
			if (parameters.put(name, param) != null) {
				reportWarning("%s: Duplicate %s %s. Replaced.".formatted(loc, AT_ENV, trimmed));
			}
		}
		catch (ParseException e) {
			reportError(e.getMessage());
		}
	}

	protected void parseHelp(Location loc, String str) {
		if (helpLocation != null) {
			reportWarning(MSGPAT_DUPLICATE_TAG.formatted(loc, AT_HELP));
		}
		String[] parts = str.trim().split("#", 2);
		if (parts.length != 2) {
			reportError(MSGPAT_INVALID_HELP_SYNTAX.formatted(loc, AT_HELP));
			return;
		}
		helpLocation = new HelpLocation(parts[0].trim(), parts[1].trim());
	}

	protected void parseIcon(Location loc, String str) {
		if (iconId != null) {
			reportWarning(MSGPAT_DUPLICATE_TAG.formatted(loc, AT_ICON));
		}
		iconId = str.trim();
		if (!Gui.hasIcon(iconId)) {
			reportError(
				"%s: Icon id %s not registered in the theme".formatted(loc, iconId));
		}
	}

	protected void parseImageOpt(Location loc, String str) {
		if (imageOptKey != null) {
			reportWarning(MSGPAT_DUPLICATE_TAG.formatted(loc, AT_IMAGE_OPT));
		}
		imageOptKey = str.strip();
	}

	protected void parseMenuGroup(Location loc, String str) {
		if (menuGroup != null) {
			reportWarning(MSGPAT_DUPLICATE_TAG.formatted(loc, AT_MENU_GROUP));
		}
		menuGroup = str;
	}

	protected void parseMenuOrder(Location loc, String str) {
		if (menuOrder != null) {
			reportWarning(MSGPAT_DUPLICATE_TAG.formatted(loc, AT_MENU_ORDER));
		}
		menuOrder = str;
	}

	protected void parseMenuPath(Location loc, String str) {
		if (menuPath != null) {
			reportWarning(MSGPAT_DUPLICATE_TAG.formatted(loc, AT_MENU_PATH));
		}
		menuPath = List.of(str.trim().split("\\."));
		if (menuPath.isEmpty()) {
			reportError(
				"%s: Empty %s. Ignoring.".formatted(loc, AT_MENU_PATH));
		}
	}

	protected void parseTimeout(Location loc, String str) {
		try {
			timeoutMillis = Integer.parseInt(str);
		}
		catch (NumberFormatException e) {
			reportError(MSGPAT_INVALID_TIMEOUT_SYNTAX.formatted(loc, AT_TIMEOUT));
		}
	}

	protected void parseTitle(Location loc, String str) {
		if (title != null) {
			reportWarning(MSGPAT_DUPLICATE_TAG.formatted(loc, AT_TITLE));
		}
		title = str;
	}

	protected void putTty(Location loc, String name, TtyCondition condition) {
		if (extraTtys.put(name, condition) != null) {
			reportWarning("%s: Duplicate %s. Ignored".formatted(loc, AT_TTY));
		}
	}

	protected void parseTty(Location loc, String str) {
		List<String> parts = ShellUtils.parseArgs(str);
		switch (parts.size()) {
			case 1 -> {
				putTty(loc, parts.get(0), ConstTtyCondition.ALWAYS);
				return;
			}
			case 3 -> {
				if ("if".equals(parts.get(1))) {
					LaunchParameter<?> param = parameters.get(parts.get(2));
					if (param == null) {
						reportError(
							MSGPAT_INVALID_TTY_NO_PARAM.formatted(loc, AT_TTY, parts.get(2)));
						return;
					}
					if (param.type() != Boolean.class) {
						reportError(
							MSGPAT_INVALID_TTY_NOT_BOOL.formatted(loc, AT_TTY, param.name()));
						return;
					}
					@SuppressWarnings("unchecked")
					LaunchParameter<Boolean> asBoolParam = (LaunchParameter<Boolean>) param;
					putTty(loc, parts.get(0), new BoolTtyCondition(asBoolParam));
					return;
				}
			}
			case 5 -> {
				if ("if".equals(parts.get(1)) && "==".equals(parts.get(3))) {
					LaunchParameter<?> param = parameters.get(parts.get(2));
					if (param == null) {
						reportError(
							MSGPAT_INVALID_TTY_NO_PARAM.formatted(loc, AT_TTY, parts.get(2)));
						return;
					}
					try {
						Object value = param.decode(parts.get(4)).val();
						putTty(loc, parts.get(0), new EqualsTtyCondition(param, value));
						return;
					}
					catch (Exception e) {
						reportError(MSGPAT_INVALID_TTY_BAD_VAL.formatted(loc, AT_TTY,
							param.name(), param.type(), parts.get(4)));
						return;
					}
				}
			}
		}
		reportError(MSGPAT_INVALID_TTY_SYNTAX.formatted(loc, AT_TTY));
	}

	protected void parseUnrecognized(Location loc, String line) {
		reportWarning("%s: Unrecognized metadata: %s".formatted(loc, line));
	}

	protected ScriptAttributes validate(String fileName) {
		if (title == null) {
			reportError(
				"%s is required. Using script file name: '%s'".formatted(AT_TITLE, fileName));
			title = fileName;
		}
		if (menuPath == null) {
			menuPath = List.of(title);
		}
		if (menuGroup == null) {
			menuGroup = "";
		}
		if (menuOrder == null) {
			menuOrder = "";
		}
		if (iconId == null) {
			iconId = "icon.debugger";
		}
		LaunchParameter<?> imageOpt = null;
		if (imageOptKey != null) {
			imageOpt = parameters.get(imageOptKey);
			if (imageOpt == null) {
				reportError("%s: %s refers to %s, which is not a parameter name".formatted(fileName,
					AT_IMAGE_OPT, imageOptKey));
			}
		}
		return new ScriptAttributes(title, getDescription(), List.copyOf(menuPath), menuGroup,
			menuOrder, new GIcon(iconId), helpLocation,
			Collections.unmodifiableMap(new LinkedHashMap<>(parameters)),
			Collections.unmodifiableMap(new LinkedHashMap<>(extraTtys)), timeoutMillis, imageOpt);
	}

	private String getDescription() {
		return description == null ? null : description.toString();
	}

	protected void reportWarning(String message) {
		Msg.warn(this, message);
	}

	protected void reportError(String message) {
		Msg.error(this, message);
	}
}
