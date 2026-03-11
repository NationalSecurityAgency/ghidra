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
package ghidra.app.plugin.processors.sleigh;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.function.Consumer;

import generic.concurrent.io.ProcessConsumer;

/**
 * Helps creating and launching a java process.
 * <p>
 * By default, the launched process will have the same classpath as the current jvm and use the
 * same java binary to start the session.
 * <p>
 * Example usage:
 * <pre>
 *   Process newproc = new JavaProcessBuilder(AClassWithMainEntryPoint.class)
 *     .addProperty("sun.java2d.opengl", "false")
 *     .addLaunchArg("-Xmx2G")
 *     .withStdoutMonitor( (s) -> System.out.println(s) )
 *     .start();
 * </pre>
 */
class JavaProcessBuilder {
	private static final String CP_SEP = System.getProperty("path.separator");

	private File javaBinary;
	private String mainClassname;
	private List<String> arguments;
	private String classPaths;
	private Map<String, String> javaProperties = new HashMap<>();
	private List<String> launchArgs = new ArrayList<>();
	private Consumer<String> stdoutMonitor;

	/**
	 * Creates a java process builder, setting the main entry point for the launched process.
	 * 
	 * @param mainClass class that contains a {@code public static void main(String[])} entry point.
	 *   Also implies that the launched process should have the same classpath as the current
	 *   jvm, or that the referenced class is somehow included in the launched process's classpath 
	 */
	public JavaProcessBuilder(Class<?> mainClass) {
		this.mainClassname = mainClass.getName();
	}

	/**
	 * Creates a java process builder, setting the main entry point for the launched process.
	 * 
	 * @param mainClassname name of a class that contains a
	 *   {@code public static void main(String[])} entry point. 
	 */
	public JavaProcessBuilder(String mainClassname) {
		this.mainClassname = mainClassname;
	}

	/**
	 * Sets the arguments for the launched processes {@code main(String[] args)} method.
	 * 
	 * @param newArguments arguments for the launched main() entry point
	 * @return chainable ref to same
	 */
	public JavaProcessBuilder withArguments(List<String> newArguments) {
		this.arguments = new ArrayList<>(newArguments);
		return this;
	}

	/**
	 * Sets the location of the java jdk install, which controls how the bin/java[.exe] is found.
	 * 
	 * @param javaHomeDir java home directory
	 * @return chainable ref to same
	 */
	public JavaProcessBuilder withJavaHome(File javaHomeDir) {
		this.javaBinary = javaHomeDir != null ? javaBinaryFromJavaHome(javaHomeDir) : null;

		return this;
	}

	private static File javaBinaryFromJavaHome(File javaHomeDir) {
		File binDir = new File(javaHomeDir, "bin");
		return new File(binDir, "java");
	}

	/**
	 * Returns the location of the java binary that will be used to launch the new process.
	 * 
	 * @return File pointing to the java jvm binary (java or java.exe)
	 */
	public File getJavaBinary() {
		File f = javaBinary;
		if (f == null) {
			f = javaBinaryFromJavaHome(new File(System.getProperty("java.home")));
		}
		return f;
	}

	/**
	 * Sets the classpaths for the launched process.  The string is expected to be delimited with
	 * the correct separators.
	 * 
	 * @param newClassPaths classpath string for the launched process
	 * @return chainable ref to same
	 */
	public JavaProcessBuilder withClasspaths(String newClassPaths) {
		this.classPaths = newClassPaths;

		return this;
	}

	/**
	 * Returns the classpath string that will be used to launch the new process.
	 * 
	 * @return string
	 */
	public String getClasspaths() {
		String s = classPaths;
		if (s == null) {
			s = System.getProperty("java.class.path");
		}
		return s;
	}

	/**
	 * Adds an element to the classpath.
	 * 
	 * @param classPath single classpath element
	 * @return chainable ref to same
	 */
	public JavaProcessBuilder addClasspath(String classPath) {
		this.classPaths = Objects.requireNonNullElse(this.classPaths, "") + CP_SEP + classPath;

		return this;
	}

	/**
	 * Sets a callback that will handle each line written to stdout by the launched process.
	 * <p>
	 * The monitor will be called an additional time with a {@code null} value after the 
	 * spawned process has exited and its stdout has emptied.
	 * 
	 * @param newStdoutMonitor Consumer<String> that will receive each text line written by
	 *   the launched process to it's stdout
	 * @return chainable ref to same
	 */
	public JavaProcessBuilder withStdoutMonitor(Consumer<String> newStdoutMonitor) {
		this.stdoutMonitor = newStdoutMonitor;

		return this;
	}

	/**
	 * Adds a java system property to the launched process (e.g. "-DpropertyName=value").
	 * 
	 * @param propertyName name of the property
	 * @param propertyValue value of the property
	 * @return chainable ref to same
	 */
	public JavaProcessBuilder addProperty(String propertyName, String propertyValue) {
		javaProperties.put(propertyName, propertyValue);

		return this;
	}

	/**
	 * Returns a list of properties that will be added to the launched process.
	 * 
	 * @return list of property definition arguments
	 */
	public List<String> getProperties() {
		return javaProperties.entrySet()
				.stream()
				.map(entry -> "-D%s=%s".formatted(entry.getKey(), entry.getValue()))
				.toList();
	}

	/**
	 * Adds a java launch argument (e.g. "-Xmx512M", etc)
	 * 
	 * @param launchArg raw argument to pass to the java binary when launching
	 * @return chainable ref to same
	 */
	public JavaProcessBuilder addLaunchArg(String launchArg) {
		launchArgs.add(launchArg);

		return this;
	}

	/**
	 * Creates a 'real' {@link ProcessBuilder} using the information specified in this builder.
	 * <p>
	 * The stdout monitor will still need to be installed into any launched process.
	 * 
	 * @return {@link ProcessBuilder}
	 */
	public ProcessBuilder getProcessBuilder() {
		Objects.requireNonNull(mainClassname);

		List<String> commandParts = new ArrayList<>();
		commandParts.add(getJavaBinary().getPath());
		commandParts.addAll(launchArgs);
		String cp = getClasspaths();
		if (!cp.isBlank()) {
			commandParts.add("-cp");
			commandParts.add(cp);
		}
		commandParts.addAll(getProperties());
		commandParts.add(mainClassname);
		commandParts.addAll(arguments != null ? arguments : List.of());

		ProcessBuilder pb = new ProcessBuilder(commandParts);
		return pb;
	}

	/**
	 * Installs a monitor that reads the processes stdout
	 * 
	 * @param process {@link Process}
	 */
	public void installMonitor(Process process) {
		ProcessConsumer.monitorAndSignalEof(process.getInputStream(), stdoutMonitor,
			"stdout[%d]".formatted(process.pid()));
	}

	/**
	 * Launches a new java process using the information specified in this builder.
	 * 
	 * @return {@link Process}
	 * @throws IOException if error starting process 
	 */
	public Process start() throws IOException {
		ProcessBuilder pb = getProcessBuilder();
		Process process = pb.start();
		if (stdoutMonitor != null) {
			installMonitor(process);
		}
		return process;
	}
}
