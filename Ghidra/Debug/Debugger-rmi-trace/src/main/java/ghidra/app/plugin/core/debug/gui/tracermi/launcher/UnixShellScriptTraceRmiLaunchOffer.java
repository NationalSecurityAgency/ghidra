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
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * A launcher implemented by a simple UNIX shell script.
 * 
 * <p>
 * The script must start with an attributes header in a comment block. Some attributes are required.
 * Others are optional:
 * <ul>
 * <li>{@code @menu-path}: <b>(Required)</b></li>
 * </ul>
 */
public class UnixShellScriptTraceRmiLaunchOffer extends AbstractTraceRmiLaunchOffer {
	public static final String SHEBANG = "#!";

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
				Msg.error(AttributesParser.class, "%s: Invalid type %s".formatted(loc, typeName));
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
		static BaseType<?> parse(Location loc, String typeName) {
			BaseType<?> type = switch (typeName) {
				case "str" -> BaseType.STRING;
				case "int" -> BaseType.INT;
				case "bool" -> BaseType.BOOL;
				default -> null;
			};
			if (type == null) {
				Msg.error(AttributesParser.class,
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
					Msg.error(AttributesParser.class,
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
					Msg.error(AttributesParser.class,
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

	protected record UserType<T> (BaseType<T> base, List<T> choices) implements OptType<T> {
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

	protected record TypeAndDefault<T> (OptType<T> type, T defaultValue) {
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

	protected static class AttributesParser {
		protected int argc = 0;
		protected String title;
		protected StringBuilder description;
		protected List<String> menuPath;
		protected String menuGroup;
		protected String menuOrder;
		protected String iconId;
		protected HelpLocation helpLocation;
		protected final Map<String, UserType<?>> userTypes = new HashMap<>();
		protected final Map<String, ParameterDescription<?>> parameters = new LinkedHashMap<>();
		protected final Set<String> extraTtys = new LinkedHashSet<>();

		/**
		 * Process a line in the metadata comment block
		 * 
		 * @param line the line, excluding any comment delimiters
		 */
		public void parseLine(Location loc, String line) {
			String afterHash = line.stripLeading().substring(1);
			if (afterHash.isBlank()) {
				return;
			}
			String[] parts = afterHash.split("\\s+", 2);
			if (!parts[0].startsWith("@")) {
				return;
			}
			if (parts.length < 2) {
				Msg.error(this, "%s: Too few tokens: %s".formatted(loc, line));
				return;
			}
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
				default -> parseUnrecognized(loc, line);
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

		protected void parseTty(Location loc, String str) {
			if (!extraTtys.add(str)) {
				Msg.warn(this, "%s: Duplicate %s. Ignored".formatted(loc, AT_TTY));
			}
		}

		protected void parseUnrecognized(Location loc, String line) {
			Msg.warn(this, "%s: Unrecognized metadata: %s".formatted(loc, line));
		}

		protected void validate(String fileName) {
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
		}

		public String getDescription() {
			return description == null ? null : description.toString();
		}
	}

	/**
	 * Create a launch offer from the given shell script.
	 * 
	 * @param program the current program, usually the target image. In general, this should be used
	 *            for at least two purposes. 1) To populate the default command line. 2) To ensure
	 *            the target image is mapped in the resulting target trace.
	 * @throws FileNotFoundException
	 */
	public static UnixShellScriptTraceRmiLaunchOffer create(Program program, PluginTool tool,
			File script) throws FileNotFoundException {
		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(new FileInputStream(script)))) {
			AttributesParser attrs = new AttributesParser();
			String line;
			for (int lineNo = 1; (line = reader.readLine()) != null; lineNo++) {
				if (line.startsWith(SHEBANG) && lineNo == 1) {
				}
				else if (line.isBlank()) {
					continue;
				}
				else if (line.stripLeading().startsWith("#")) {
					attrs.parseLine(new Location(script.getName(), lineNo), line);
				}
				else {
					break;
				}
			}
			attrs.validate(script.getName());
			return new UnixShellScriptTraceRmiLaunchOffer(program, tool, script,
				"UNIX_SHELL:" + script.getName(), attrs.title, attrs.getDescription(),
				attrs.menuPath, attrs.menuGroup, attrs.menuOrder, new GIcon(attrs.iconId),
				attrs.helpLocation, attrs.parameters, attrs.extraTtys);
		}
		catch (FileNotFoundException e) {
			// Avoid capture by IOException
			throw e;
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	protected final File script;
	protected final String configName;
	protected final String title;
	protected final String description;
	protected final List<String> menuPath;
	protected final String menuGroup;
	protected final String menuOrder;
	protected final Icon icon;
	protected final HelpLocation helpLocation;
	protected final Map<String, ParameterDescription<?>> parameters;
	protected final List<String> extraTtys;

	public UnixShellScriptTraceRmiLaunchOffer(Program program, PluginTool tool, File script,
			String configName, String title, String description, List<String> menuPath,
			String menuGroup, String menuOrder, Icon icon, HelpLocation helpLocation,
			Map<String, ParameterDescription<?>> parameters, Collection<String> extraTtys) {
		super(program, tool);
		this.script = script;
		this.configName = configName;
		this.title = title;
		this.description = description;
		this.menuPath = List.copyOf(menuPath);
		this.menuGroup = menuGroup;
		this.menuOrder = menuOrder;
		this.icon = icon;
		this.helpLocation = helpLocation;
		this.parameters = Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
		this.extraTtys = List.copyOf(extraTtys);
	}

	@Override
	public String getConfigName() {
		return configName;
	}

	@Override
	public String getTitle() {
		return title;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public List<String> getMenuPath() {
		return menuPath;
	}

	@Override
	public String getMenuGroup() {
		return menuGroup;
	}

	@Override
	public String getMenuOrder() {
		return menuOrder;
	}

	@Override
	public Icon getIcon() {
		return icon;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return helpLocation;
	}

	@Override
	public Map<String, ParameterDescription<?>> getParameters() {
		return parameters;
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

	@Override
	protected void launchBackEnd(TaskMonitor monitor, Map<String, TerminalSession> sessions,
			Map<String, ?> args, SocketAddress address) throws Exception {
		List<String> commandLine = new ArrayList<>();
		Map<String, String> env = new HashMap<>(System.getenv());

		commandLine.add(script.getAbsolutePath());
		env.put("GHIDRA_HOME", Application.getInstallationDirectory().getAbsolutePath());
		env.put("GHIDRA_TRACE_RMI_ADDR", sockToString(address));

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

		for (String tty : extraTtys) {
			NullPtyTerminalSession ns = nullPtyTerminal();
			env.put(tty, ns.name());
			sessions.put(ns.name(), ns);
		}

		sessions.put("Shell", runInTerminal(commandLine, env, sessions.values()));
	}
}
