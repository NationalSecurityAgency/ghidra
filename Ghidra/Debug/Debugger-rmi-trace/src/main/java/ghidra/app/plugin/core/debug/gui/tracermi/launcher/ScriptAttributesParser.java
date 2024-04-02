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
import java.util.*;
import java.util.Map.Entry;

import javax.swing.Icon;

import generic.theme.GIcon;
import generic.theme.Gui;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.util.ShellUtils;
import ghidra.framework.Application;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * A parser for reading attributes from a script header
 */
public abstract class ScriptAttributesParser {
	public static final String AT_TITLE = "@title";
	public static final String AT_DESC = "@desc";
	public static final String AT_MENU_PATH = "@menu-path";
	public static final String AT_MENU_GROUP = "@menu-group";
	public static final String AT_MENU_ORDER = "@menu-order";
	public static final String AT_ICON = "@icon";
	public static final String AT_HELP = "@help";
	public static final String AT_ENUM = "@enum";
	public static final String AT_ENV = "@env";
	public static final String AT_ARG = "@arg";
	public static final String AT_ARGS = "@args";
	public static final String AT_TTY = "@tty";
	public static final String AT_TIMEOUT = "@timeout";
	public static final String AT_NOIMAGE = "@no-image";

	public static final String PREFIX_ENV = "env:";
	public static final String PREFIX_ARG = "arg:";
	public static final String KEY_ARGS = "args";

	public static final String MSGPAT_INVALID_HELP_SYNTAX =
		"%s: Invalid %s syntax. Use Topic#anchor";
	public static final String MSGPAT_INVALID_ENUM_SYNTAX =
		"%s: Invalid %s syntax. Use NAME:type Choice1 [ChoiceN...]";
	public static final String MSGPAT_INVALID_ENV_SYNTAX =
		"%s: Invalid %s syntax. Use NAME:type=default \"Display\" \"Tool Tip\"";
	public static final String MSGPAT_INVALID_ARG_SYNTAX =
		"%s: Invalid %s syntax. Use :type \"Display\" \"Tool Tip\"";
	public static final String MSGPAT_INVALID_ARGS_SYNTAX =
		"%s: Invalid %s syntax. Use \"Display\" \"Tool Tip\"";
	public static final String MSGPAT_INVALID_TTY_SYNTAX =
		"%s: Invalid %s syntax. Use TTY_TARGET [if env:OPT_EXTRA_TTY]";
	public static final String MSGPAT_INVALID_TIMEOUT_SYNTAX = "" +
		"%s: Invalid %s syntax. Use [milliseconds]";

	protected record Location(String fileName, int lineNo) {
		@Override
		public String toString() {
			return "%s:%d".formatted(fileName, lineNo);
		}
	}

	protected interface OptType<T> {
		static OptType<?> parse(Location loc, String typeName,
				Map<String, UserType<?>> userEnums) {
			OptType<?> type = switch (typeName) {
				case "str" -> BaseType.STRING;
				case "int" -> BaseType.INT;
				case "bool" -> BaseType.BOOL;
				default -> userEnums.get(typeName);
			};
			if (type == null) {
				Msg.error(ScriptAttributesParser.class,
					"%s: Invalid type %s".formatted(loc, typeName));
				return null;
			}
			return type;
		}

		default TypeAndDefault<T> withCastDefault(Object defaultValue) {
			return new TypeAndDefault<>(this, cls().cast(defaultValue));
		}

		Class<T> cls();

		T decode(Location loc, String str);

		ParameterDescription<T> createParameter(String name, T defaultValue, String display,
				String description);
	}

	protected interface BaseType<T> extends OptType<T> {
		public static BaseType<?> parse(Location loc, String typeName) {
			BaseType<?> type = switch (typeName) {
				case "str" -> BaseType.STRING;
				case "int" -> BaseType.INT;
				case "bool" -> BaseType.BOOL;
				default -> null;
			};
			if (type == null) {
				Msg.error(ScriptAttributesParser.class,
					"%s: Invalid base type %s".formatted(loc, typeName));
				return null;
			}
			return type;
		}

		public static final BaseType<String> STRING = new BaseType<>() {
			@Override
			public Class<String> cls() {
				return String.class;
			}

			@Override
			public String decode(Location loc, String str) {
				return str;
			}
		};

		public static final BaseType<BigInteger> INT = new BaseType<>() {
			@Override
			public Class<BigInteger> cls() {
				return BigInteger.class;
			}

			@Override
			public BigInteger decode(Location loc, String str) {
				try {
					if (str.startsWith("0x")) {
						return new BigInteger(str.substring(2), 16);
					}
					return new BigInteger(str);
				}
				catch (NumberFormatException e) {
					Msg.error(ScriptAttributesParser.class,
						("%s: Invalid int for %s: %s. You may prefix with 0x for hexadecimal. " +
							"Otherwise, decimal is used.").formatted(loc, AT_ENV, str));
					return null;
				}
			}
		};

		public static final BaseType<Boolean> BOOL = new BaseType<>() {
			@Override
			public Class<Boolean> cls() {
				return Boolean.class;
			}

			@Override
			public Boolean decode(Location loc, String str) {
				Boolean result = switch (str) {
					case "true" -> true;
					case "false" -> false;
					default -> null;
				};
				if (result == null) {
					Msg.error(ScriptAttributesParser.class,
						"%s: Invalid bool for %s: %s. Only true or false (in lower case) is allowed."
								.formatted(loc, AT_ENV, str));
					return null;
				}
				return result;
			}
		};

		default UserType<T> withCastChoices(List<?> choices) {
			return new UserType<>(this, choices.stream().map(cls()::cast).toList());
		}

		@Override
		default ParameterDescription<T> createParameter(String name, T defaultValue, String display,
				String description) {
			return ParameterDescription.create(cls(), name, false, defaultValue, display,
				description);
		}
	}

	protected record UserType<T>(BaseType<T> base, List<T> choices) implements OptType<T> {
		@Override
		public Class<T> cls() {
			return base.cls();
		}

		@Override
		public T decode(Location loc, String str) {
			return base.decode(loc, str);
		}

		@Override
		public ParameterDescription<T> createParameter(String name, T defaultValue, String display,
				String description) {
			return ParameterDescription.choices(cls(), name, choices, defaultValue, display,
				description);
		}
	}

	protected record TypeAndDefault<T>(OptType<T> type, T defaultValue) {
		public static TypeAndDefault<?> parse(Location loc, String typeName, String defaultString,
				Map<String, UserType<?>> userEnums) {
			OptType<?> tac = OptType.parse(loc, typeName, userEnums);
			if (tac == null) {
				return null;
			}
			Object value = tac.decode(loc, defaultString);
			if (value == null) {
				return null;
			}
			return tac.withCastDefault(value);
		}

		public ParameterDescription<T> createParameter(String name, String display,
				String description) {
			return type.createParameter(name, defaultValue, display, description);
		}
	}

	public interface TtyCondition {
		boolean isActive(Map<String, ?> args);
	}

	enum ConstTtyCondition implements TtyCondition {
		ALWAYS {
			@Override
			public boolean isActive(Map<String, ?> args) {
				return true;
			}
		},
	}

	record EqualsTtyCondition(String key, String repr) implements TtyCondition {
		@Override
		public boolean isActive(Map<String, ?> args) {
			return Objects.toString(args.get(key)).equals(repr);
		}
	}

	record BoolTtyCondition(String key) implements TtyCondition {
		@Override
		public boolean isActive(Map<String, ?> args) {
			return args.get(key) instanceof Boolean b && b.booleanValue();
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
			Map<String, ParameterDescription<?>> parameters, Map<String, TtyCondition> extraTtys,
			int timeoutMillis, boolean noImage) {
	}

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
			File script, Map<String, ParameterDescription<?>> parameters, Map<String, ?> args,
			SocketAddress address) {

		commandLine.add(script.getAbsolutePath());
		env.put("GHIDRA_HOME", Application.getInstallationDirectory().getAbsolutePath());
		if (address != null) {
			env.put("GHIDRA_TRACE_RMI_ADDR", sockToString(address));
			if (address instanceof InetSocketAddress tcp) {
				env.put("GHIDRA_TRACE_RMI_HOST", tcp.getAddress().getHostAddress());
				env.put("GHIDRA_TRACE_RMI_PORT", Integer.toString(tcp.getPort()));
			}
		}

		ParameterDescription<?> paramDesc;
		for (int i = 1; (paramDesc = parameters.get("arg:" + i)) != null; i++) {
			commandLine.add(Objects.toString(paramDesc.get(args)));
		}

		paramDesc = parameters.get("args");
		if (paramDesc != null) {
			commandLine.addAll(ShellUtils.parseArgs((String) paramDesc.get(args)));
		}

		for (Entry<String, ParameterDescription<?>> ent : parameters.entrySet()) {
			String key = ent.getKey();
			if (key.startsWith(PREFIX_ENV)) {
				String varName = key.substring(PREFIX_ENV.length());
				env.put(varName, Objects.toString(ent.getValue().get(args)));
			}
		}
	}

	private int argc = 0;
	private String title;
	private StringBuilder description;
	private List<String> menuPath;
	private String menuGroup;
	private String menuOrder;
	private String iconId;
	private HelpLocation helpLocation;
	private final Map<String, UserType<?>> userTypes = new HashMap<>();
	private final Map<String, ParameterDescription<?>> parameters = new LinkedHashMap<>();
	private final Map<String, TtyCondition> extraTtys = new LinkedHashMap<>();
	private int timeoutMillis = AbstractTraceRmiLaunchOffer.DEFAULT_TIMEOUT_MILLIS;
	private boolean noImage = false;

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

	public ScriptAttributes parseFile(File script) throws FileNotFoundException {
		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(new FileInputStream(script)))) {
			String line;
			for (int lineNo = 1; (line = reader.readLine()) != null; lineNo++) {
				if (ignoreLine(lineNo, line)) {
					continue;
				}
				String comment = removeDelimiter(line);
				if (comment == null) {
					break;
				}
				parseComment(new Location(script.getName(), lineNo), comment);
			}
			return validate(script.getName());
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
			switch (parts[0].trim()) {
				case AT_NOIMAGE -> parseNoImage(loc);
				default -> parseUnrecognized(loc, comment);
			}
		}
		else {
			switch (parts[0].trim()) {
				case AT_TITLE -> parseTitle(loc, parts[1]);
				case AT_DESC -> parseDesc(loc, parts[1]);
				case AT_MENU_PATH -> parseMenuPath(loc, parts[1]);
				case AT_MENU_GROUP -> parseMenuGroup(loc, parts[1]);
				case AT_MENU_ORDER -> parseMenuOrder(loc, parts[1]);
				case AT_ICON -> parseIcon(loc, parts[1]);
				case AT_HELP -> parseHelp(loc, parts[1]);
				case AT_ENUM -> parseEnum(loc, parts[1]);
				case AT_ENV -> parseEnv(loc, parts[1]);
				case AT_ARG -> parseArg(loc, parts[1], ++argc);
				case AT_ARGS -> parseArgs(loc, parts[1]);
				case AT_TTY -> parseTty(loc, parts[1]);
				case AT_TIMEOUT -> parseTimeout(loc, parts[1]);
				default -> parseUnrecognized(loc, comment);
			}
		}
	}

	protected void parseTitle(Location loc, String str) {
		if (title != null) {
			Msg.warn(this, "%s: Duplicate @title".formatted(loc));
		}
		title = str;
	}

	protected void parseDesc(Location loc, String str) {
		if (description == null) {
			description = new StringBuilder();
		}
		description.append(str);
		description.append("\n");
	}

	protected void parseMenuPath(Location loc, String str) {
		if (menuPath != null) {
			Msg.warn(this, "%s: Duplicate %s".formatted(loc, AT_MENU_PATH));
		}
		menuPath = List.of(str.trim().split("\\."));
		if (menuPath.isEmpty()) {
			Msg.error(this,
				"%s: Empty %s. Ignoring.".formatted(loc, AT_MENU_PATH));
		}
	}

	protected void parseMenuGroup(Location loc, String str) {
		if (menuGroup != null) {
			Msg.warn(this, "%s: Duplicate %s".formatted(loc, AT_MENU_GROUP));
		}
		menuGroup = str;
	}

	protected void parseMenuOrder(Location loc, String str) {
		if (menuOrder != null) {
			Msg.warn(this, "%s: Duplicate %s".formatted(loc, AT_MENU_ORDER));
		}
		menuOrder = str;
	}

	protected void parseIcon(Location loc, String str) {
		if (iconId != null) {
			Msg.warn(this, "%s: Duplicate %s".formatted(loc, AT_ICON));
		}
		iconId = str.trim();
		if (!Gui.hasIcon(iconId)) {
			Msg.error(this,
				"%s: Icon id %s not registered in the theme".formatted(loc, iconId));
		}
	}

	protected void parseHelp(Location loc, String str) {
		if (helpLocation != null) {
			Msg.warn(this, "%s: Duplicate %s".formatted(loc, AT_HELP));
		}
		String[] parts = str.trim().split("#", 2);
		if (parts.length != 2) {
			Msg.error(this, MSGPAT_INVALID_HELP_SYNTAX.formatted(loc, AT_HELP));
			return;
		}
		helpLocation = new HelpLocation(parts[0].trim(), parts[1].trim());
	}

	protected void parseEnum(Location loc, String str) {
		List<String> parts = ShellUtils.parseArgs(str);
		if (parts.size() < 2) {
			Msg.error(this, MSGPAT_INVALID_ENUM_SYNTAX.formatted(loc, AT_ENUM));
			return;
		}
		String[] nameParts = parts.get(0).split(":", 2);
		if (nameParts.length != 2) {
			Msg.error(this, MSGPAT_INVALID_ENUM_SYNTAX.formatted(loc, AT_ENUM));
			return;
		}
		String name = nameParts[0].trim();
		BaseType<?> baseType = BaseType.parse(loc, nameParts[1]);
		if (baseType == null) {
			return;
		}
		List<?> choices = parts.stream().skip(1).map(s -> baseType.decode(loc, s)).toList();
		if (choices.contains(null)) {
			return;
		}
		UserType<?> userType = baseType.withCastChoices(choices);
		if (userTypes.put(name, userType) != null) {
			Msg.warn(this, "%s: Duplicate %s %s. Replaced.".formatted(loc, AT_ENUM, name));
		}
	}

	protected void parseEnv(Location loc, String str) {
		List<String> parts = ShellUtils.parseArgs(str);
		if (parts.size() != 3) {
			Msg.error(this, MSGPAT_INVALID_ENV_SYNTAX.formatted(loc, AT_ENV));
			return;
		}
		String[] nameParts = parts.get(0).split(":", 2);
		if (nameParts.length != 2) {
			Msg.error(this, MSGPAT_INVALID_ENV_SYNTAX.formatted(loc, AT_ENV));
			return;
		}
		String trimmed = nameParts[0].trim();
		String name = PREFIX_ENV + trimmed;
		String[] tadParts = nameParts[1].split("=", 2);
		if (tadParts.length != 2) {
			Msg.error(this, MSGPAT_INVALID_ENV_SYNTAX.formatted(loc, AT_ENV));
			return;
		}
		TypeAndDefault<?> tad =
			TypeAndDefault.parse(loc, tadParts[0].trim(), tadParts[1].trim(), userTypes);
		ParameterDescription<?> param = tad.createParameter(name, parts.get(1), parts.get(2));
		if (parameters.put(name, param) != null) {
			Msg.warn(this, "%s: Duplicate %s %s. Replaced.".formatted(loc, AT_ENV, trimmed));
		}
	}

	protected void parseArg(Location loc, String str, int argNum) {
		List<String> parts = ShellUtils.parseArgs(str);
		if (parts.size() != 3) {
			Msg.error(this, MSGPAT_INVALID_ARG_SYNTAX.formatted(loc, AT_ARG));
			return;
		}
		String colonType = parts.get(0).trim();
		if (!colonType.startsWith(":")) {
			Msg.error(this, MSGPAT_INVALID_ARG_SYNTAX.formatted(loc, AT_ARG));
			return;
		}
		OptType<?> type = OptType.parse(loc, colonType.substring(1), userTypes);
		if (type == null) {
			return;
		}
		String name = PREFIX_ARG + argNum;
		parameters.put(name, ParameterDescription.create(type.cls(), name, true, null,
			parts.get(1), parts.get(2)));
	}

	protected void parseArgs(Location loc, String str) {
		List<String> parts = ShellUtils.parseArgs(str);
		if (parts.size() != 2) {
			Msg.error(this, MSGPAT_INVALID_ARGS_SYNTAX.formatted(loc, AT_ARGS));
			return;
		}
		ParameterDescription<String> parameter = ParameterDescription.create(String.class,
			"args", false, "", parts.get(0), parts.get(1));
		if (parameters.put(KEY_ARGS, parameter) != null) {
			Msg.warn(this, "%s: Duplicate %s. Replaced".formatted(loc, AT_ARGS));
		}
	}

	protected void putTty(Location loc, String name, TtyCondition condition) {
		if (extraTtys.put(name, condition) != null) {
			Msg.warn(this, "%s: Duplicate %s. Ignored".formatted(loc, AT_TTY));
		}
	}

	protected void parseTty(Location loc, String str) {
		List<String> parts = ShellUtils.parseArgs(str);
		switch (parts.size()) {
			case 1:
				putTty(loc, parts.get(0), ConstTtyCondition.ALWAYS);
				return;
			case 3:
				if ("if".equals(parts.get(1))) {
					putTty(loc, parts.get(0), new BoolTtyCondition(parts.get(2)));
					return;
				}
			case 5:
				if ("if".equals(parts.get(1)) && "==".equals(parts.get(3))) {
					putTty(loc, parts.get(0), new EqualsTtyCondition(parts.get(2), parts.get(4)));
					return;
				}
		}
		Msg.error(this, MSGPAT_INVALID_TTY_SYNTAX.formatted(loc, AT_TTY));
	}

	protected void parseTimeout(Location loc, String str) {
		try {
			timeoutMillis = Integer.parseInt(str);
		}
		catch (NumberFormatException e) {
			Msg.error(this, MSGPAT_INVALID_TIMEOUT_SYNTAX.formatted(loc, AT_TIMEOUT));
		}
	}

	protected void parseNoImage(Location loc) {
		noImage = true;
	}

	protected void parseUnrecognized(Location loc, String line) {
		Msg.warn(this, "%s: Unrecognized metadata: %s".formatted(loc, line));
	}

	protected ScriptAttributes validate(String fileName) {
		if (title == null) {
			Msg.error(this, "%s is required. Using script file name.".formatted(AT_TITLE));
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
		return new ScriptAttributes(title, getDescription(), List.copyOf(menuPath), menuGroup,
			menuOrder, new GIcon(iconId), helpLocation,
			Collections.unmodifiableMap(new LinkedHashMap<>(parameters)),
			Collections.unmodifiableMap(new LinkedHashMap<>(extraTtys)), timeoutMillis, noImage);
	}

	private String getDescription() {
		return description == null ? null : description.toString();
	}
}
