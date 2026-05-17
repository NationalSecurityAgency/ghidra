/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Formatter;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

/**
 * Headless benchmark for comparing legacy and native intra-function parallel decompilation.
 *
 * Args:
 *   workers minOps maxFunctions mode outDir
 *
 * mode:
 *   legacy  -> native option disabled
 *   staged  -> native staged option enabled
 */
public class ParallelIntraFunctionDecompileBenchmark extends GhidraScript {
	private static class Result {
		String mode;
		int workers;
		int minOps;
		int functions;
		long elapsedMs;
		String sha256;
		Path output;
	}

	private static String sha256(String data) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(data.getBytes(StandardCharsets.UTF_8));
		try (Formatter fmt = new Formatter()) {
			for (byte b : digest) {
				fmt.format("%02x", b);
			}
			return fmt.toString();
		}
	}

	private Result runMode(String mode, int workers, int minOps, int maxFunctions, Path outDir)
			throws Exception {
		boolean parallel = "staged".equals(mode);
		DecompileOptions opts = new DecompileOptions();
		opts.grabFromProgram(currentProgram);
		if (parallel) {
			opts.setNativeParallelDecompile(true, workers, minOps);
		}

		DecompInterface ifc = new DecompInterface();
		try {
			ifc.setOptions(opts);
			ifc.openProgram(currentProgram);

			List<Function> funcs = new ArrayList<>();
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (!f.isThunk()) {
					funcs.add(f);
				}
			}
			funcs.sort(Comparator.comparing(Function::getEntryPoint));

			StringBuilder normalized = new StringBuilder();
			long start = System.nanoTime();
			int count = 0;
			for (Function f : funcs) {
				monitor.checkCancelled();
				if (maxFunctions > 0 && count >= maxFunctions) {
					break;
				}
				DecompileResults res = ifc.decompileFunction(f, 60, monitor);
				normalized.append("### ")
						.append(f.getEntryPoint())
						.append(' ')
						.append(f.getName(true))
						.append('\n');
				if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
					normalized.append(res.getDecompiledFunction().getC()).append('\n');
				}
				else {
					normalized.append("<FAILED>");
					if (res != null) {
						normalized.append(' ').append(res.getErrorMessage());
					}
					normalized.append('\n');
				}
				count++;
			}
			long elapsed = (System.nanoTime() - start) / 1_000_000L;

			Files.createDirectories(outDir);
			Path output = outDir.resolve(mode + "_decompile_output.txt");
			Files.write(output, normalized.toString().getBytes(StandardCharsets.UTF_8));

			Result r = new Result();
			r.mode = mode;
			r.workers = parallel ? workers : 1;
			r.minOps = minOps;
			r.functions = count;
			r.elapsedMs = elapsed;
			r.sha256 = sha256(normalized.toString());
			r.output = output;
			return r;
		}
		finally {
			ifc.dispose();
		}
	}

	@Override
	protected void run() throws Exception {
		String[] argv = getScriptArgs();
		int workers = argv.length > 0 ? Integer.parseInt(argv[0]) : 2;
		int minOps = argv.length > 1 ? Integer.parseInt(argv[1]) : 4096;
		int maxFunctions = argv.length > 2 ? Integer.parseInt(argv[2]) : 0;
		String mode = argv.length > 3 ? argv[3] : "legacy";
		Path outDir = argv.length > 4 ? Paths.get(argv[4]) : Paths.get("/tmp");

		Result r = runMode(mode, workers, minOps, maxFunctions, outDir);
		String csv = "mode,workers,minOps,functions,elapsedMs,sha256,output\n" +
			r.mode + "," + r.workers + "," + r.minOps + "," + r.functions + "," +
			r.elapsedMs + "," + r.sha256 + "," + r.output + "\n";
		Files.write(outDir.resolve(mode + "_decompile_benchmark.csv"),
			csv.getBytes(StandardCharsets.UTF_8));

		println(csv);
	}
}
