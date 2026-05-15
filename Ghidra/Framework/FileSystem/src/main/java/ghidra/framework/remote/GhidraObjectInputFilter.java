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
package ghidra.framework.remote;

import java.io.*;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import generic.jar.ResourceFile;
import ghidra.framework.Application;

/**
 * {@link GhidraObjectInputFilter} provides global serial input filter for use with Ghidra server
 * and client applications.  This filter primarily targets RMI deserialization, however as a 
 * global filter it impacts all deserialization cases which may need to be considered
 * when specifying filters.
 * <p>
 * Filter files use syntax as supported by {@link java.io.ObjectInputFilter.Config#createFilter(String)}
 * with the addition of {@code remoteIf=&lt;remote-classname&gt;} entries for client filters to 
 * specify those {@link Remote} interfaces which require the use of dynamic {@link Proxy} class
 * implementations for RMI stubs.
 * <p>
 * RMI Server applications should invoke {@link #configureServerSerialFilter(ResourceFile, Supplier)}
 * during early initialization with a suitable filter file, while Ghidra client applications should
 * invoke {@link #configureClientSerialFilter()} to use all Module data {@code *.serial.filter} files
 * to define client deserialization restrictions.
 * 
 * See {@link java.io.ObjectInputFilter.Config#createFilter(String)} for filter file syntax.
 * See {@link java.io.ObjectInputFilter.Config#setSerialFilterFactory(java.util.function.BinaryOperator)}.
 */
public class GhidraObjectInputFilter implements ObjectInputFilter {

	private static final String README_PATH =
		"Ghidra/Framework/FileSystem/data/serialFilterREADME.md";

	private static final Logger log = LogManager.getLogger(GhidraObjectInputFilter.class);

	private static final String FILTER_SEARCH_EXTENSION = ".serial.filter";

	private static final String REMOTE_INTERFACE = "remoteIf"; // RMI Remote Interface

	private static final String MAXARRAY = "maxarray";
	private static final String MAXREFS = "maxrefs";
	private static final String MAXDEPTH = "maxdepth";
	private static final String MAXBYTES = "maxbytes";

	// NOTE: Be sure to update serialFilterREADME.md if values are updated.
	private int MAXARRAY_DEFAULT = 32_000;
	private int MAXREFS_DEFAULT = 10_000;
	private int MAXDEPTH_DEFAULT = 50;
	private int MAXBYTES_DEFAULT = 32 * 1024 * 1024; // 32MB

	private long maxArray;
	private long maxRefs;
	private long maxDepth;
	private long maxBytes;

	private final Set<Class<?>> allowedRemoteInterfaces = new HashSet<>();
	private final AtomicReference<ObjectInputFilter> patternFilterRef = new AtomicReference<>();
	private final AtomicReference<Supplier<String>> sourceSupplierRef = new AtomicReference<>();

	// NOTE: When class tracking is enabled all class deserializations will be permitted and 
	// all filters will be ignored.  An normal process shutdown will dump the list of deserialized 
	// classes to the file TRACKER_LOG_FILE.

	// IMPORTANT: TRACKER_ENABLED must be set to 'false' when comitted to source control !!

	private static final boolean TRACKER_ENABLED = false; // class tracking enablement
	private Map<String, ClassInfo> classTracker = new TreeMap<>(); // classnames -> ClassInfo
	private File trackerLogFile;

	/**
	 * Construct global serial input filter.
	 * 
	 * NOTE: Caller is responsible for installing this instance.
	 * @throws IllegalStateException if this filter has previously been instantiated.
	 */
	GhidraObjectInputFilter() throws IllegalStateException {
		// Lazy initialization will occur during application initialization.
		// See configure methods.
	}

	private void initializeFilter(List<ResourceFile> filterFiles,
			Supplier<String> sourceNameSupplier)
			throws IllegalStateException {

		if (TRACKER_ENABLED) {
			log.warn(
				"Object deserialization filter tracking enabled! All deserializations will be ALLOWED.");
		}

		ObjectInputFilter filter;
		try {
			String filterText = readSerialFilterFiles(filterFiles);

			// Include limits if missing from filter text
			if (maxArray <= 0) {
				maxArray = MAXARRAY_DEFAULT;
				filterText += MAXARRAY + "=" + MAXARRAY_DEFAULT + ";";
			}
			if (maxRefs <= 0) {
				maxRefs = MAXREFS_DEFAULT;
				filterText += MAXREFS + "=" + MAXREFS_DEFAULT + ";";
			}
			if (maxDepth <= 0) {
				maxDepth = MAXDEPTH_DEFAULT;
				filterText += MAXDEPTH + "=" + MAXDEPTH_DEFAULT + ";";
			}
			if (maxBytes <= 0) {
				maxBytes = MAXBYTES_DEFAULT;
				filterText += MAXBYTES + "=" + MAXBYTES_DEFAULT + ";";
			}

			// Generate serial filter
			filter = ObjectInputFilter.Config.createFilter(filterText);
		}
		catch (Exception e) {
			throw new IllegalStateException("Failed to build serial input filter", e);
		}

		if (!sourceSupplierRef.compareAndSet(null, sourceNameSupplier) ||
			!patternFilterRef.compareAndSet(null, filter)) {
			throw new IllegalStateException("Serial input filter previously initialized");
		}
	}


	@Override
	public Status checkInput(FilterInfo info) {

		if (TRACKER_ENABLED) {
			trackClassDeserialization(info);
			return Status.UNDECIDED;
		}

		ObjectInputFilter patternFilter = patternFilterRef.get();
		if (patternFilter == null) {
			// Uninitialized filter state.
			// NOTE: This mode is required to facilitate lazy initialization due to 
			// Gradle testing frameworks use of serialization.
			return Status.UNDECIDED;
		}

		if (info.references() > maxRefs) {
			return serialReject(info, "maxrefs exceeded: " + info.references());
		}

		if (info.depth() > maxDepth) {
			return serialReject(info, "maxdepth exceeded: " + info.depth());
		}

		if (info.streamBytes() > maxBytes) {
			return serialReject(info, "maxbytes exceeded: " + info.streamBytes());
		}

		Class<?> clazz = info.serialClass();
		if (clazz != null) {

			// Allow all primitive arrays
			if (clazz.isArray()) {

				if (info.arrayLength() > maxArray) {
					return serialReject(info, "maxarray exceeded: " + info.arrayLength());
				}

				Class<?> componentType = clazz.getComponentType();
				if (componentType != null && componentType.isPrimitive()) {
					return Status.ALLOWED; // allow all primitive arrays
				}
			}

			// Check for allowed RMI Remote Proxies 
			else if (clazz.getPackageName().startsWith("jdk.proxy") && Proxy.isProxyClass(clazz)) {
				Class<?>[] interfaces = clazz.getInterfaces();
				for (Class<?> iface : interfaces) {
					if (allowedRemoteInterfaces.contains(iface)) {
						return Status.ALLOWED;
					}
				}
				return serialReject(info, "unknown proxy");
			}
		}

		// Give serial filter patterns first shot
		Status status = patternFilter.checkInput(info);
		if (status == Status.ALLOWED) {
			return status;
		}

		if (clazz == null) {
			return Status.UNDECIDED;
		}


		return serialReject(info, "not allowed");
	}

	private static class ClassInfo {
		private final String classname;
		private final String module;
		private long maxArrayLength;
		private long maxDepth;
		private long maxRefs;
		private long maxBytes;

		ClassInfo(FilterInfo info) {
			Class<?> clazz = info.serialClass();
			classname = clazz.getName();
			module = clazz.getModule().getName();
			maxArrayLength = info.arrayLength();
			maxDepth = info.depth();
			maxRefs = info.references();
			maxBytes = info.streamBytes();
		}

		ClassInfo(String csv) {
			String[] csvValues = csv.split(",");
			if (csvValues.length != 6) {
				throw new IllegalArgumentException("Invalid ClassInfo csv");
			}
			classname = csvValues[0].trim();
			module = csvValues[1].trim();
			maxArrayLength = Long.parseLong(csvValues[2]);
			maxDepth = Long.parseLong(csvValues[3]);
			maxRefs = Long.parseLong(csvValues[4]);
			maxBytes = Long.parseLong(csvValues[5]);
		}

		void update(FilterInfo info) {
			maxArrayLength = Math.max(maxArrayLength, info.arrayLength());
			maxDepth = Math.max(maxDepth, info.depth());
			maxRefs = Math.max(maxRefs, info.references());
			maxBytes = Math.max(maxBytes, info.streamBytes());
		}

		@Override
		public String toString() {
			return String.format("%s,%s,%d,%d,%d,%d", classname, module, maxArrayLength, maxDepth,
				maxRefs, maxBytes);
		}

		static String getCSVHeader() {
			return "Classname, module, max-array-length, max-depth, max-Refs";
		}
	}

	private void trackClassDeserialization(FilterInfo info) {
		Class<?> clazz = info.serialClass();
		if (clazz == null) {
			return;
		}

		if (classTracker.isEmpty()) {
			log.info(
				"Installing deserialization class tracking: " + trackerLogFile);
			Thread hook = new Thread(() -> {
				List<String> list = classTracker.keySet().stream().collect(Collectors.toList());
				Collections.sort(list);
				try (FileWriter w = new FileWriter(trackerLogFile)) {
					w.append("# " + ClassInfo.getCSVHeader() + "\n");
					for (String s : list) {
						w.append(classTracker.get(s) + "\n");
					}
				}
				catch (IOException e) {
					// ignore - logging may be limited
				}
			});
			Runtime.getRuntime().addShutdownHook(hook);

			// Consume previously recorded class names
			if (trackerLogFile.isFile()) {
				try (BufferedReader r =
					new BufferedReader(new FileReader(trackerLogFile))) {
					for (String line = r.readLine(); line != null; line = r.readLine()) {
						line = line.trim();
						if (!line.isEmpty() && !line.startsWith("#")) {
							ClassInfo classInfo = new ClassInfo(line);
							classTracker.put(classInfo.classname, classInfo);
						}
					}
				}
				catch (IOException e) {
					log.error("Error when consuming file: " + trackerLogFile + "\n", e);
				}
			}
		}

		String classname = clazz.getName();
		ClassInfo classInfo = classTracker.get(classname);
		if (classInfo != null) {
			classInfo.update(info);
		}
		else {
			classTracker.put(classname, new ClassInfo(info));
		}
	}

	/**
	 * Get the class serialization source.
	 * If a {@link #sourceSupplierRef} has been set it will be used, otherwise null will be returned.
	 * 
	 * @return serialized data source name or null
	 */
	protected String getSourceName() {
		Supplier<String> supplier = sourceSupplierRef.get();
		return supplier != null ? supplier.get() : null;
	}

	private Status serialReject(FilterInfo info, String reason) {
		String dataSourceName = getSourceName();
		StringBuilder buf = new StringBuilder();
		buf.append("Rejected class serialization");
		if (dataSourceName != null) {
			buf.append(" from ");
			buf.append(dataSourceName);
		}
		buf.append("(");
		buf.append(reason);
		buf.append(")");

		Class<?> serialClass = info.serialClass();
		if (serialClass != null) {
			buf.append(": ");
			buf.append(serialClass.getCanonicalName());
			buf.append(" ");
			if (serialClass.getComponentType() != null) {
				buf.append("(");
				buf.append("array-length=");
				buf.append(info.arrayLength());
				buf.append(")");
			}
		}

		buf.append(" (see " + README_PATH + ")");

		log.error(buf.toString());
		return Status.REJECTED;
	}

	private String readSerialFilterFiles(List<ResourceFile> filterFiles) throws IOException {

		LinkedHashSet<String> filterSet = new LinkedHashSet<>(); // preserves order while preventing duplicates
		for (ResourceFile filterFile : filterFiles) {
			if (!filterFile.exists()) {
				throw new FileNotFoundException("Serialization filter not found: " + filterFile);
			}

			ResourceFile p1 = filterFile.getParentFile();
			ResourceFile p2 = p1.getParentFile();
			String path = p2.getName() + "/" + p1.getName() + "/" + filterFile.getName();
			log.debug("Including serial input filter: " + path);

			try (InputStream in = filterFile.getInputStream()) {
				try {
					readFilterEntries(in, filterSet);
				}
				catch (IllegalArgumentException | IOException e) {
					throw new IOException(
						"Failed to parse serialization filter file: " + filterFile, e);
				}
			}
		}
		return filterSet.stream().collect(Collectors.joining());
	}

	/**
	 * Read specified serialization filter file content removing any comments and newlines and generate 
	 * corresponding {@link ObjectInputFilter}.
	 * @param in filter file input stream
	 * @param filterSet filter text accumulator set (eliminates duplicate entries).
	 * @throws IOException if file error occurs
	 */
	private void readFilterEntries(InputStream in, Set<String> filterSet)
			throws IOException {
		try (BufferedReader r = new BufferedReader(new InputStreamReader(in))) {
			for (String line = r.readLine(); line != null; line = r.readLine()) {
				int ix = line.indexOf('#');
				if (ix >= 0) {
					// strip comment
					line = line.substring(0, ix);
				}
				line = line.trim();
				if (line.length() == 0) {
					continue;
				}
				if (!line.endsWith(";")) {
					throw new IllegalArgumentException(
						"All filter statements must end with `;`");
				}
				if (line.startsWith("!")) {
					throw new IllegalArgumentException(
						"The class rejection prefix '!' is not supported");
				}
				if (line.indexOf('=') > 0 && consumeSpecialValue(line)) {
					continue;
				}
				if (line.length() != 0) {
					filterSet.add(line);
				}
			}
		}
	}

	/**
	 * Check for special filter assignment values. 
	 * @param line filter line
	 * @return true if entry fully consumed and should be excluded from 
	 *  {@link java.io.ObjectInputFilter.Config#createFilter(String)} filter text.
	 */
	private boolean consumeSpecialValue(String line) {

		int equalIx = line.indexOf('=');
		String name = line.substring(0, equalIx);
		String valueStr = line.substring(equalIx + 1, line.length() - 1);
		
		if (REMOTE_INTERFACE.equals(name)) {
			// Add allowed Remote interface for proxies
			try {
				Class<?> ifClass = Class.forName(valueStr);
				if (Remote.class.isAssignableFrom(ifClass)) {
					allowedRemoteInterfaces.add(ifClass);
					return true;
				}
			}
			catch (ClassNotFoundException e) {
				// ignore
			}
			throw new IllegalArgumentException(
				"Invalid remote interface '" + valueStr + "'");
		}

		try {
			if (MAXARRAY.equals(name)) {
				maxArray = Math.max(maxArray, parseLong(name, valueStr, MAXARRAY_DEFAULT));
			}
			else if (MAXREFS.equals(name)) {
				maxRefs = Math.max(maxRefs, parseLong(name, valueStr, MAXREFS_DEFAULT));
			}
			else if (MAXDEPTH.equals(name)) {
				maxDepth = Math.max(maxDepth, parseLong(name, valueStr, MAXDEPTH_DEFAULT));
			}
			else if (MAXBYTES.equals(name)) {
				maxBytes = Math.max(maxBytes, parseLong(name, valueStr, MAXBYTES_DEFAULT));
			}
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException(
				"Invalid '" + name + "' filter value: " + valueStr);
		}
		return false; // include in filter
	}

	private long parseLong(String name, String valueStr, long defaultMin) {
		long value = Long.parseLong(valueStr);
		if (value <= 0) {
			throw new NumberFormatException("Positive value required");
		}
		if (value < defaultMin) {
			log.warn("Ignoring '" + name + "=" + valueStr +
				"' serial filter entry which is less than " + defaultMin);
			return -1; // ignore entry
		}
		return value;
	}

	/**
	 * Install global deserialization filter factory for a server.  This will handle all 
	 * deserialization filtering including SignedObject payloads.
	 * <p>
	 * This filter will make use of the {@link GhidraSerialFilterFactory} and ensure that it is
	 * properly installed.
	 * 
	 * @param filterFile serial filter file
	 * @param sourceNameSupplier source name supplied for use during logging, or null.  It 
	 * is assumed that a the current thread may be used to differentiate a client connection
	 * over which the serialization is occuring.
	 * @throws IllegalStateException if error occured building or installing serial input filter
	 * and related filter factory.
	 */
	public static void configureServerSerialFilter(ResourceFile filterFile,
			Supplier<String> sourceNameSupplier) throws IllegalStateException {

		Objects.requireNonNull(filterFile, "Serial filter resource file is required");

		GhidraObjectInputFilter serialFilter =
			GhidraSerialFilterFactory.getOrInstallInstance().getSerialFilter();
		serialFilter.trackerLogFile =
			new File(Application.getUserTempDirectory(), "SerialLogServer.txt");
		serialFilter.initializeFilter(List.of(filterFile), sourceNameSupplier);
	}

	/**
	 * Configure global serial input filter for a client.  This will handle all 
	 * deserialization filtering including SignedObject payloads.  The object deserialization 
	 * filter will be based on the accumulation of all {@code data/*.serial.filter} files found 
	 * within all Application modules.
	 * <p>
	 * This filter will make use of the {@link GhidraSerialFilterFactory} and ensure that it is
	 * properly installed.
	 * 
	 * @throws IllegalStateException if error occured building or installing serial input filter
	 * and related filter factory.
	 */
	public static synchronized void configureClientSerialFilter()
			throws IllegalStateException {

		List<ResourceFile> filterFiles =
			Application.findFilesByExtensionInApplication(FILTER_SEARCH_EXTENSION);
		if (filterFiles.isEmpty()) {
			log.warn("No serial input filter files were found (*" +
				FILTER_SEARCH_EXTENSION + ")");
		}

		GhidraObjectInputFilter serialFilter =
			GhidraSerialFilterFactory.getOrInstallInstance().getSerialFilter();
		serialFilter.trackerLogFile =
			new File(Application.getUserTempDirectory(), "SerialLogClient.txt");
		serialFilter.initializeFilter(filterFiles, null);
	}

}
