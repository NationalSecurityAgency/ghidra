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
import ghidra.async.AsyncUtils;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;

public class GdbModuleImpl implements GdbModule {
	protected static final Pattern OBJECT_FILE_LINE_PATTERN =
		Pattern.compile("\\s*Object file: (?<name>.*)");

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

	protected Pattern sectionLinePattern = OBJECT_SECTION_LINE_PATTERN_V10;

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
		return inferior.loadSections().thenCompose(__ -> {
			if (!loadSections.isDone()) {
				/**
				 * The inferior's load sections should have provided the value out of band before it
				 * is completed from the request that got us invoked. If it didn't it's because the
				 * response to the load in progress did not include this module. We should only have
				 * to force it at most once more.
				 */
				inferior.loadSections.forget();
				return inferior.loadSections();
			}
			return AsyncUtils.NIL;
		}).thenAccept(__ -> {
			if (!loadSections.isDone()) {
				Msg.warn(this,
					"Module's sections still not known: " + name + ". Probably got unloaded.");
			}
		});
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

	protected Matcher matchSectionLine(Pattern pattern, String line) {
		Matcher matcher = pattern.matcher(line);
		if (matcher.matches()) {
			sectionLinePattern = pattern;
		}
		return matcher;
	}

	protected Matcher matchSectionLine(String line) {
		Matcher matcher = sectionLinePattern.matcher(line);
		if (matcher.matches()) {
			return matcher;
		}
		matcher = matchSectionLine(OBJECT_SECTION_LINE_PATTERN_V10, line);
		if (matcher.matches()) {
			return matcher;
		}
		matcher = matchSectionLine(OBJECT_SECTION_LINE_PATTERN_V8, line);
		if (matcher.matches()) {
			return matcher;
		}
		return matcher;
	}

	protected void processSectionLine(String line) {
		Matcher matcher = matchSectionLine(line);
		if (matcher.matches()) {
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
