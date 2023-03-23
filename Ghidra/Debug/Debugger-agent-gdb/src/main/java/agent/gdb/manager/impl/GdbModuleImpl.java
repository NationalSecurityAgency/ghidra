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
package agent.gdb.manager.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import agent.gdb.manager.GdbModule;
import agent.gdb.manager.GdbModuleSection;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import ghidra.async.AsyncLazyValue;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;

public class GdbModuleImpl implements GdbModule {
	protected static final String MAINT_INFO_SECTIONS_CMD_V8 =
		"maintenance info sections ALLOBJ";
	protected static final String MAINT_INFO_SECTIONS_CMD_V11 =
		"maintenance info sections -all-objects";
	protected static final String[] MAINT_INFO_SECTIONS_CMDS = new String[] {
		MAINT_INFO_SECTIONS_CMD_V11,
		MAINT_INFO_SECTIONS_CMD_V8,
	};

	protected static final Pattern OBJECT_FILE_LINE_PATTERN_V8 =
		Pattern.compile("\\s*Object file: (?<name>.*)");
	protected static final Pattern OBJECT_FILE_LINE_PATTERN_V11 =
		Pattern.compile("\\s*((Object)|(Exec)) file: `(?<name>.*)', file type (?<type>.*)");

	protected static final Pattern[] OBJECT_FILE_LINE_PATTERNS = new Pattern[] {
		OBJECT_FILE_LINE_PATTERN_V11,
		OBJECT_FILE_LINE_PATTERN_V8,
	};

	protected static final String GNU_DEBUGDATA_PREFIX = ".gnu_debugdata for ";

	// Pattern observed in GDB 8 (probably applies to previous, too)
	protected static final Pattern OBJECT_SECTION_LINE_PATTERN_V8 = Pattern.compile(
		"\\s*" + //
			"0x(?<vmaS>[0-9A-Fa-f]+)\\s*->\\s*" + //
			"0x(?<vmaE>[0-9A-Fa-f]+)\\s+at\\s+" + //
			"0x(?<offset>[0-9A-Fa-f]+)\\s*:\\s*" + //
			"(?<name>\\S+)\\s+" + //
			"(?<attrs>.*)");

	// Pattern observed in GDB 10 (may apply in 9, too)
	protected static final Pattern OBJECT_SECTION_LINE_PATTERN_V10 = Pattern.compile(
		"\\s*" + //
			"\\[\\s*(?<idx>\\d+)\\]\\s+" + //
			"0x(?<vmaS>[0-9A-Fa-f]+)\\s*->\\s*" + //
			"0x(?<vmaE>[0-9A-Fa-f]+)\\s+at\\s+" + //
			"0x(?<offset>[0-9A-Fa-f]+)\\s*:\\s*" + //
			"(?<name>\\S+)\\s+" + //
			"(?<attrs>.*)");

	protected static final Pattern[] OBJECT_SECTION_LINE_PATTERNS = new Pattern[] {
		OBJECT_SECTION_LINE_PATTERN_V10,
		OBJECT_SECTION_LINE_PATTERN_V8,
	};

	protected static final Pattern MSYMBOL_LINE_PATTERN = Pattern.compile(
		"\\s*" + //
			"\\[\\s*(?<idx>\\d+)\\]\\s+" + //
			"(?<type>\\S+)\\s+" + //
			"0x(?<addr>[0-9A-Fa-f]+)\\s+" + //
			"(?<name>\\S+)\\s+" + //
			".*");

	protected final GdbInferiorImpl inferior;
	protected final String name;
	protected Long base = null;
	protected Long max = null;

	protected final Map<String, GdbModuleSectionImpl> sections = new LinkedHashMap<>();
	protected final Map<String, GdbModuleSection> unmodifiableSections =
		Collections.unmodifiableMap(sections);
	protected final AsyncLazyValue<Void> loadSections = new AsyncLazyValue<>(this::doLoadSections);

	protected final AsyncLazyValue<Map<String, GdbMinimalSymbol>> minimalSymbols =
		new AsyncLazyValue<>(this::doGetMinimalSymbols);

	public GdbModuleImpl(GdbInferiorImpl inferior, String name) {
		this.inferior = inferior;
		this.name = name;
	}

	@Override
	public String getName() {
		return name;
	}

	protected CompletableFuture<Void> doLoadSections() {
		return inferior.doLoadSections();
	}

	@Override
	public CompletableFuture<Long> computeBase() {
		return loadSections.request().thenApply(__ -> base);
	}

	@Override
	public CompletableFuture<Long> computeMax() {
		return loadSections.request().thenApply(__ -> max);
	}

	@Override
	public Long getKnownBase() {
		return base;
	}

	@Override
	public Long getKnownMax() {
		return max;
	}

	@Override
	public CompletableFuture<Map<String, GdbModuleSection>> listSections() {
		if (sections.isEmpty() && loadSections.isDone()) {
			loadSections.forget();
		}
		return loadSections.request().thenApply(__ -> unmodifiableSections);
	}

	@Override
	public Map<String, GdbModuleSection> getKnownSections() {
		return unmodifiableSections;
	}

	protected CompletableFuture<Map<String, GdbMinimalSymbol>> doGetMinimalSymbols() {
		// TODO: Apparently, this is using internal GDB-debugging commands....
		// TODO: Also make methods for "full" symbols (DWARF?)
		String cmd = "maintenance print msymbols -objfile " + name;
		return inferior.consoleCapture(cmd, CompletesWithRunning.CANNOT).thenApply(out -> {
			Map<String, GdbMinimalSymbol> result = new LinkedHashMap<>();
			for (String line : out.split("\n")) {
				Matcher mat = MSYMBOL_LINE_PATTERN.matcher(line);
				if (!mat.matches()) {
					continue;
				}
				long index = Long.parseLong(mat.group("idx"));
				String type = Objects.requireNonNull(mat.group("type"));
				long address = Long.parseLong(mat.group("addr"), 16);
				String symName = Objects.requireNonNull(mat.group("name"));
				result.put(symName, new GdbMinimalSymbol(index, type, symName, address));
			}
			return Collections.unmodifiableMap(result);
		});
	}

	@Override
	public CompletableFuture<Map<String, GdbMinimalSymbol>> listMinimalSymbols() {
		// TODO: getKnownMinimalSymbols method, too?
		return minimalSymbols.request();
	}

	protected void processSectionLine(String line) {
		Matcher matcher = inferior.manager.matchSectionLine(line);
		if (matcher != null) {
			try {
				long vmaStart = Long.parseLong(matcher.group("vmaS"), 16);
				long vmaEnd = Long.parseLong(matcher.group("vmaE"), 16);
				long offset = Long.parseLong(matcher.group("offset"), 16);

				String sectionName = matcher.group("name");
				List<String> attrs = new ArrayList<>();
				for (String a : matcher.group("attrs").split("\\s+")) {
					if (a.length() != 0) {
						attrs.add(a);
					}
				}
				if (attrs.contains("ALLOC")) {
					long b = vmaStart - offset;
					base = base == null ? b : MathUtilities.unsignedMin(base, b);
					max = max == null ? b : MathUtilities.unsignedMax(max, vmaEnd);
				}
				if (sections.put(sectionName,
					new GdbModuleSectionImpl(sectionName, vmaStart, vmaEnd, offset,
						attrs)) != null) {
					Msg.warn(this, "Duplicate section name: " + line);
				}
			}
			catch (NumberFormatException e) {
				Msg.error(this, "Invalid number in section entry: " + line);
			}
		}
	}
}
