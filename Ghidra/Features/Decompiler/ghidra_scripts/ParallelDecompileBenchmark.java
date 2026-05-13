/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
// Decompiles every function in the current program either sequentially or with a bounded worker pool.
// @category Decompiler
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

import generic.concurrent.GThreadPool;
import generic.concurrent.QCallback;
import generic.concurrent.QResult;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

public class ParallelDecompileBenchmark extends GhidraScript {

	private static class Item {
		String key;
		String c;
		String err;
		Item(String key, String c, String err) {
			this.key = key;
			this.c = c;
			this.err = err;
		}
	}

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs(getScriptArgs());
		String mode = args.getOrDefault("mode", "old");
		int workers = Math.max(1, Integer.parseInt(args.getOrDefault("workers", "1")));
		int timeout = Math.max(1, Integer.parseInt(args.getOrDefault("timeout", "60")));
		int maxFunctions = Math.max(0, Integer.parseInt(args.getOrDefault("maxFunctions", "0")));
		Path outDir = Paths.get(args.getOrDefault("out", "/tmp/ghidra-decompile-" + mode));
		Files.createDirectories(outDir);

		List<Function> functions = new ArrayList<>();
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		while (it.hasNext()) {
			Function f = it.next();
			if (!f.isThunk()) {
				functions.add(f);
				if (maxFunctions > 0 && functions.size() >= maxFunctions) {
					break;
				}
			}
		}

		long start = System.nanoTime();
		List<Item> items;
		if ("new".equalsIgnoreCase(mode) || "parallel".equalsIgnoreCase(mode)) {
			items = parallel(functions, workers, timeout);
		}
		else {
			items = sequential(functions, timeout);
		}
		long elapsedNanos = System.nanoTime() - start;

		items.sort(Comparator.comparing(i -> i.key));
		Path combined = outDir.resolve("decompiled-" + mode + ".txt");
		try (BufferedWriter w = Files.newBufferedWriter(combined, StandardCharsets.UTF_8)) {
			for (Item i : items) {
				w.write("===== " + i.key + " =====\n");
				if (i.err != null) {
					w.write("/* ERROR: " + i.err.replace("\n", " ") + " */\n");
				}
				else {
					w.write(i.c == null ? "" : i.c);
					if (i.c == null || !i.c.endsWith("\n")) {
						w.write("\n");
					}
				}
			}
		}

		Path csv = outDir.resolve("timing-" + mode + ".csv");
		try (BufferedWriter w = Files.newBufferedWriter(csv, StandardCharsets.UTF_8)) {
			w.write("program,mode,workers,functions,elapsed_ms,combined_output\n");
			w.write(csv(currentProgram.getName()) + "," + csv(mode) + "," + workers + "," +
				functions.size() + "," + (elapsedNanos / 1_000_000L) + "," + csv(combined.toString()) + "\n");
		}

		printf("ParallelDecompileBenchmark: mode=%s workers=%d functions=%d elapsed_ms=%d out=%s\n",
			mode, workers, functions.size(), elapsedNanos / 1_000_000L, combined);
	}

	private List<Item> sequential(List<Function> functions, int timeout) throws Exception {
		List<Item> out = new ArrayList<>();
		DecompInterface ifc = new DecompInterface();
		try {
			ifc.openProgram(currentProgram);
			for (Function f : functions) {
				monitor.checkCancelled();
				out.add(decompileOne(ifc, f, timeout, monitor));
				monitor.incrementProgress(1);
			}
		}
		finally {
			ifc.dispose();
		}
		return out;
	}

	private List<Item> parallel(List<Function> functions, int workers, int timeout) throws Exception {
		ConcurrentLinkedQueue<DecompInterface> interfaces = new ConcurrentLinkedQueue<>();
		ThreadLocal<DecompInterface> localIfc = ThreadLocal.withInitial(() -> {
			DecompInterface ifc = new DecompInterface();
			ifc.openProgram(currentProgram);
			interfaces.add(ifc);
			return ifc;
		});

		QCallback<Function, Item> callback = new QCallback<Function, Item>() {
			@Override
			public Item process(Function f, TaskMonitor m) throws Exception {
				return decompileOne(localIfc.get(), f, timeout, m);
			}
		};

		GThreadPool pool = GThreadPool.getPrivateThreadPool("Bounded Parallel Decompiler");
		pool.setMaxThreadCount(workers);
		pool.setMinThreadCount(0);

		DecompilerConcurrentQ<Function, Item> queue =
			new DecompilerConcurrentQ<>(callback, pool, true, monitor);
		monitor.initialize(functions.size());
		try {
			queue.addAll(functions);
			Collection<QResult<Function, Item>> qResults = queue.waitForResults();
			List<Item> results = new ArrayList<>();
			for (QResult<Function, Item> r : qResults) {
				results.add(r.getResult());
			}
			return results;
		}
		finally {
			queue.dispose(5);
			pool.shutdownNow();
			for (DecompInterface ifc : interfaces) {
				ifc.dispose();
			}
		}
	}

	private Item decompileOne(DecompInterface ifc, Function f, int timeout, TaskMonitor m) {
		String key = f.getEntryPoint().toString() + " " + f.getName(true);
		try {
			DecompileResults res = ifc.decompileFunction(f, timeout, m);
			if (!res.decompileCompleted()) {
				return new Item(key, null, res.getErrorMessage());
			}
			DecompiledFunction df = res.getDecompiledFunction();
			return new Item(key, df == null ? "" : df.getC(), null);
		}
		catch (Throwable t) {
			return new Item(key, null, t.toString());
		}
	}

	private Map<String, String> parseArgs(String[] argv) {
		Map<String, String> map = new HashMap<>();
		for (String a : argv) {
			int ix = a.indexOf('=');
			if (ix > 0) {
				map.put(a.substring(0, ix), a.substring(ix + 1));
			}
		}
		return map;
	}

	private String csv(String s) {
		if (s == null) {
			return "";
		}
		return "\"" + s.replace("\"", "\"\"") + "\"";
	}
}
