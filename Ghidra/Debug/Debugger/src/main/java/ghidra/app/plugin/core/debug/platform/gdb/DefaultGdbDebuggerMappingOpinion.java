package ghidra.app.plugin.core.debug.platform.gdb;

import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOffer;
import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOpinion;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;

public class DefaultGdbDebuggerMappingOpinion implements DebuggerMappingOpinion {
	public static final String EXTERNAL_TOOL = "gnu";
	public static final CompilerSpecID PREFERRED_CSPEC_ID = new CompilerSpecID("gcc");

	private static final Map<Pair<String, Endian>, List<LanguageCompilerSpecPair>> CACHE =
		new HashMap<>();

	protected static class GdbDefaultOffer extends AbstractGdbDebuggerMappingOffer {
		public GdbDefaultOffer(TargetObject target, int confidence, String description,
				LanguageCompilerSpecPair lcsp, Collection<String> extraRegNames) {
			super(target, confidence, description, lcsp.languageID, lcsp.compilerSpecID,
				extraRegNames);
		}
	}

	public static List<LanguageCompilerSpecPair> getCompilerSpecsForGnu(String arch,
			Endian endian) {
		synchronized (CACHE) {
			return CACHE.computeIfAbsent(Pair.of(arch, endian), p -> {
				LanguageService langServ = DefaultLanguageService.getLanguageService();
				return langServ.getLanguageCompilerSpecPairs(
					new ExternalLanguageCompilerSpecQuery(arch, EXTERNAL_TOOL,
						endian, null, PREFERRED_CSPEC_ID));
			});
		}
	}

	public static boolean isGdb(TargetEnvironment env) {
		if (env == null) {
			return false;
		}
		if (!env.getDebugger().toLowerCase().contains("gdb")) {
			return false;
		}
		return true;
	}

	public static boolean isLinux(TargetEnvironment env) {
		if (env == null) {
			return false;
		}
		if (!env.getOperatingSystem().contains("Linux")) {
			return false;
		}
		return true;
	}

	public static Endian getEndian(TargetEnvironment env) {
		String strEndian = env.getEndian();
		if (strEndian.contains("little")) {
			return Endian.LITTLE;
		}
		// TODO: Do I care if it's Linux? I really don't think so.
		if (strEndian.contains("big")) {
			return Endian.BIG;
		}
		return null;
	}

	protected Collection<String> getExtraRegNames() {
		return Set.of();
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process) {
		if (!isGdb(env)) {
			return Set.of();
		}
		Endian endian = getEndian(env);
		String arch = env.getArchitecture();

		return getCompilerSpecsForGnu(arch, endian).stream().map(lcsp -> {
			return new GdbDefaultOffer(process, 10, "Default GDB for " + arch, lcsp,
				getExtraRegNames());
		}).collect(Collectors.toSet());
	}
}
