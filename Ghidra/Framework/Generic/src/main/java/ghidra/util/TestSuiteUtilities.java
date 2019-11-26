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
package ghidra.util;

import java.io.*;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import ghidra.util.exception.AssertException;
import junit.framework.TestSuite;
import utilities.util.FileUtilities;

/**
 * A set of static utilities to facilitate JUnit testing.
 */
public class TestSuiteUtilities {
	
	private static final char JAR_FILE_SEPARATOR = '/';

	private static Class<?> TEST_CASE_CLASS = createTestClass();
	private static Class<?> createTestClass() {
		try {
			return Class.forName("junit.framework.TestCase");
		} catch (ClassNotFoundException e) {
			throw new AssertException();
		}
	}
	
	/**
	 * Build JUnit test suite for the specified package.
	 * TestSuite includes sub-TestSuites for each sub-package.
	 * @param pkgName the java package name
	 * @return test suite
	 */
	public static TestSuite getTestSuite(String pkgName) {
		return getTestSuite(pkgName, true);
	}
	
	/**
	 * Build JUnit test suite for the specified package only.
	 * @param pkgName the java package name
	 * @return test suite
	 */
	public static TestSuite getPkgTestSuite(String pkgName) {
		return getTestSuite(pkgName, false);
	}
	
	private static TestSuite getTestSuite(String pkgName, boolean recurse) {
	
		TestSuite suite = new TestSuite();
		suite.setName("[Package] " + pkgName);
		
		// Add all TestCases contained within the specified package
		Iterator<String> iter = getClassNames(pkgName, TEST_CASE_CLASS);
		while (iter.hasNext()) {
			String name = iter.next();
			try {
				suite.addTest(new TestSuite(Class.forName(name)));
			} catch (ClassNotFoundException e) {
				System.out.println("Failed to load test case: " + name);
			}
		}
		
		// Recursively add TestSuites associated with sub-packages
		if (recurse) {
			iter = getSubPkgNames(pkgName);
			while (iter.hasNext()) {
				String subPkgName = iter.next();
				TestSuite ts = getTestSuite(subPkgName, true);
				if (ts.countTestCases() > 0) {
					suite.addTest(ts);
				}
			}
		}
		
		return suite;	
	}
	
	private static boolean hasTests(String pkgName, boolean recurse) {
	
		// Check for TestCases within the specified package
		Iterator<String> iter = getClassNames(pkgName, TEST_CASE_CLASS);
		if (iter.hasNext()) 
			return true;
		
		// Recursively check for TestCases within sub-packages
		if (recurse) {
			iter = getSubPkgNames(pkgName);
			while (iter.hasNext()) {
				String subPkgName = iter.next();
				if (hasTests(subPkgName, true))
					return true;
			}
		}
		
		return false;	
	}


    /**
     * Get all class names within the named package which extend or implement the 
     * specified search class.
     * @param pkgName package name
     * @param searchClass base or interface class to search for.
     */
    public static Iterator<String> getClassNames(String pkgName, Class<?> searchClass) {
        	
        HashSet<String> classNames = new HashSet<String>();

        String classPath = System.getProperty("java.class.path");
        if (classPath == null || classPath.trim().length() == 0) {
            classPath = System.getProperty("user.dir");
        }
        String javaHome = System.getProperty("java.home");

        StringTokenizer st = new StringTokenizer(classPath, File.pathSeparator);
        
        while (st.hasMoreElements()) {
            String path = (String)st.nextElement();
            if (path.startsWith(javaHome)) {
                continue;
            }
            
            if (path.endsWith(".jar") || path.endsWith(".zip")) {
                // look for all classes in the class path
                findClassesInJar(path, pkgName, searchClass, classNames);
            }
            else {
                File f = new File(path);
                if (!f.isDirectory()) {
                    continue;
                }
                findClassesInPath(path, pkgName, searchClass, classNames);
            }
        }
        return classNames.iterator();
    }
    
    /**
     * Find and add to classNames, all classes within the classpath and the specified package 
     * which extend or implement the specified searchClass.
     * @param classPath directory path that is from CLASSPATH
     * @param pkgName name of package
     * @param searchClass base or interface class to search for.
     * @param classNames set of unique class names
     */
    private static void findClassesInPath(String classPath, String pkgName, Class<?> searchClass, HashSet<String> classNames) {

        // make sure the classPath is complete
        File cfile = new File(classPath);
        String absolutePath = cfile.getAbsolutePath();
        if (!classPath.equals(absolutePath)) {
            classPath = absolutePath;
        }
        if (!classPath.endsWith(File.separator)) {
            // append the separator so the substring works correctly
            // below when we build the class name to pass to the loader...
            classPath = classPath + File.separator;
        }
        String pkgPath = pkgName.replace('.', File.separatorChar);	
        classPath += pkgPath;

        File dir = new File(classPath);
        String []names = dir.list();
        
        if (names == null) {
            return; // not a directory
        }

        for (String name : names) {

            File f = new File(dir, name);
            String filename = f.getAbsolutePath();
            
            if (f.isDirectory() || !filename.endsWith(".class")) {
                continue;  // file is not a class file
            }

            // Make sure we use the class name and not
            // a filename so that the system can load it...
            // generate the class name to pass to loadClass(), so
            // use classPath to chop off the part we don't want in the
            // class name. 
            //
            String className = createClassName(filename, pkgName, File.separatorChar);
            if (!classNames.contains(className)) {
	            try {
	            	Class<?> c = Class.forName(className);
	            	if (isClassOfInterest(c, searchClass)) {
	            		classNames.add(className);
	            	}
	            } catch (Throwable t) {
	                // ignore linkage errors...
	                if (!(t instanceof LinkageError)) {
	                    System.out.println("Error loading class " +
	                                       filename + ", " + t);
	                }
	            }
            }
        }
    }
    
    /**
     * Find and add to classNames, all classes within a jar file and the specified package 
     * which extend or implement the specified searchClass.
     * @param jarFilename jar filename
     * @param pkgName name of package
     * @param searchClass base or interface class to search for.
     * @param classNames set of unique class names
     */
	private static void findClassesInJar(String jarFilename, String pkgName, Class<?> searchClass,
			HashSet<String> classNames) {

		try (JarFile jarFile = new JarFile(jarFilename)) {

			String pkgPath = pkgName != null ? pkgName.replace('.', JAR_FILE_SEPARATOR) : "";
			if (pkgPath.length() > 0) {
				pkgPath += JAR_FILE_SEPARATOR;
			}
			int lastSepIx = pkgPath.length() - 1;

			Enumeration<JarEntry> entries = jarFile.entries();
			while (entries.hasMoreElements()) {
				JarEntry entry = entries.nextElement();
				String name = entry.getName();
				if (!name.endsWith(".class")) {
					continue; // file is not a class file
				}
				if ((lastSepIx != -1 && name.indexOf(pkgPath) != 0) ||
					name.lastIndexOf(JAR_FILE_SEPARATOR) != lastSepIx) {
					continue; // file not contained within specified package
				}

				String className = createClassName(name, pkgName, JAR_FILE_SEPARATOR);
				if (!classNames.contains(className)) {
					try {
						Class<?> c = Class.forName(className);
						if (isClassOfInterest(c, searchClass)) {
							classNames.add(className);
						}
					}
					catch (Throwable t) {
						continue;
					}
				}
			}
		}
		catch (IOException e) {
			//System.out.println("searchJarFile: " + e);
			return;
		}
	}

    /**
     * Create a java class name from the given filename and class path.
     * @param filename filename that has the class path pre-pended to it.
     * @param pkgName name of package
     * @param fileSep file separator used within filename ('/' or '\').
     * @return String
     */
    private static String createClassName(String filename, String pkgName, char fileSep) {
    	String pkgPath = pkgName != null ? pkgName.trim() : "";
    	if (pkgPath.length() > 0 && !pkgPath.endsWith(".")) {
    		pkgPath += ".";
    	}
    	String name = filename.substring(0, filename.indexOf(".class"));
    	int ix = name.lastIndexOf(fileSep);
    	if (ix >= 0) {
    		name = name.substring(ix+1);
    	}
    	return pkgPath + name;
    }

    /**
     * Return true if c is a derivative of the filter class 
     * and is not abstract.
     */
    private static boolean isClassOfInterest(Class<?> c, Class<?> searchClass) {
        boolean isAbstract = Modifier.isAbstract(c.getModifiers());
        return searchClass.isAssignableFrom(c) && !isAbstract;
    }
    
    /**
     * Get all potential package names within the named package.
     * @param pkgName package name
     */
    public static Iterator<String> getSubPkgNames(String pkgName) {
        	
        HashSet<String> pkgNames = new HashSet<String>();

        String classPath = System.getProperty("java.class.path");
        if (classPath == null || classPath.trim().length() == 0) {
            classPath = System.getProperty("user.dir");
        }
        String javaHome = System.getProperty("java.home");

        StringTokenizer st = new StringTokenizer(classPath, File.pathSeparator);
        
        while (st.hasMoreElements()) {
            String path = (String)st.nextElement();
            if (path.startsWith(javaHome)) {
                continue;
            }
            
            if (path.endsWith(".jar") || path.endsWith(".zip")) {
                // look for all classes in the class path
                findPkgsInJar(path, pkgName, pkgNames);
            }
            else {
                File f = new File(path);
                if (!f.isDirectory()) {
                    continue;
                }
                findPkgsInPath(path, pkgName, pkgNames);
            }
        }
        return pkgNames.iterator();
    }

    /**
     * Find and add to pkgNames, all packages contained within the specified package
     * @param classPath directory path that is from CLASSPATH
     * @param pkgName name of package
     * @param searchClass base or interface class to search for.
     * @param classNames set of unique class names
     */
    private static void findPkgsInPath(String classPath, String pkgName, HashSet<String> pkgNames) {

        // make sure the classPath is complete
        File cfile = new File(classPath);
        String absolutePath = cfile.getAbsolutePath();
        if (!classPath.equals(absolutePath)) {
            classPath = absolutePath;
        }
        if (!classPath.endsWith(File.separator)) {
            // append the separator so the substring works correctly
            // below when we build the class name to pass to the loader...
            classPath = classPath + File.separator;
        }
        String pkgPath = pkgName != null ? pkgName.replace('.', File.separatorChar) : "";
        classPath += pkgPath;
        
        String pkgPrefix = pkgName;
        if (pkgName != null && pkgName.length() > 0) {
        		pkgPrefix += '.';
        }

        File dir = new File(classPath);
        String[] names = dir.list();
        
        if (names == null) {
            return; // not a directory
        }

        for (String name : names) {
            File f = new File(dir, name);
            if (f.isDirectory()) {
				String subPkgName = pkgPrefix + f.getName();
	            if (!pkgNames.contains(subPkgName)) {
	            	pkgNames.add(subPkgName);
	            }
            }
        }
    }
    /**
     * Find and add to pkgNames, all packages contained within the specified package
     * which contain an AllTests class.
     * @param jarFilename jar filename
     * @param pkgName name of package
     * @param searchClass base or interface class to search for.
     * @param classNames set of unique class names
     */
	private static void findPkgsInJar(String jarFilename, String pkgName,
			HashSet<String> pkgNames) {

		try (JarFile jarFile = new JarFile(jarFilename);) {

			String pkgPath = pkgName != null ? pkgName.replace('.', JAR_FILE_SEPARATOR) : "";
			if (pkgPath.length() > 0) {
				pkgPath += JAR_FILE_SEPARATOR;
			}
			int lastSepIx = pkgPath.length() - 1;

			String pkgPrefix = pkgName;
			if (pkgName != null && pkgName.length() > 0) {
				pkgPrefix += '.';
			}

			Enumeration<JarEntry> entries = jarFile.entries();
			while (entries.hasMoreElements()) {
				JarEntry entry = entries.nextElement();
				String name = entry.getName();
				if (!name.endsWith(".class")) {
					continue; // file is not a class file
				}
				if (lastSepIx != -1) {
					if (name.indexOf(pkgPath) != 0) {
						continue; // file not contained within specified package
					}
					name = name.substring(lastSepIx + 1);
				}
				int ix = name.indexOf(JAR_FILE_SEPARATOR);
				if (ix > 0) {
					name = pkgPrefix + name.substring(0, ix);
					if (!pkgNames.contains(name)) {
						pkgNames.add(name);
					}
				}
			}
		}
		catch (IOException e) {
			//System.out.println("searchJarFile: " + e);
			return;
		}
	}
    
    private static final String ALL_TESTS_CODE =
    	"package %PACKAGE%;\n" +
		"import ghidra.util.TestUtilities;\n" +
		"import junit.framework.Test;\n" +
		"\n" +
		"/**\n" +
		" * Generic test suite for single package.\n" +
		" */\n" +
		"public class %CLASSNAME% {\n" +
		"	public static Test suite() {\n" +
		"		%CLASSNAME% testAll = new %CLASSNAME%();\n" +
		"		return TestUtilities.getPkgTestSuite(testAll.getClass().getPackage().getName());\n" +
		"	}\n" +
		"}\n";
    
    /**
     * Create the Java source file a JUnit TestSuite which 
     * includes all TestCases within a package directory.
     * @param baseDir the base package directory
     * @param className the class name
     * @param pkgName the java package name
	 * @throws IOException
     */
    public static void createTestSuites(File baseDir, String className, String pkgName) throws IOException {
    	File dir = makeDir(baseDir, pkgName);
    	String srcCode = ALL_TESTS_CODE.replaceAll("%CLASSNAME%", className);
    	srcCode = srcCode.replaceAll("%PACKAGE%", pkgName);
    	FileWriter out = null;
		try {
			out = new FileWriter(new File(dir, className + ".java"));
			out.write(srcCode);
		} finally {
			if (out != null) {
				try { out.close(); } catch (IOException e) {}
			}
		}
    }
    
    /**
     * Create the Java source file a JUnit TestSuite which 
     * includes all TestCases within a package directory.
     * @param baseDir
     * @param className
     * @param pkgName
     * @param recurse
     */
    public static int createTestSuites(File baseDir, String className, String pkgName, boolean recurse) throws IOException {
    	
    	int cnt = 0;
    	
    	// Create TestSuite for specified package
    	if (hasTests(pkgName, false)) {
    		createTestSuites(baseDir, className, pkgName);
    		++cnt;
    	}
    	
    	// Recursively create TestSuites for all sub-packages which contain TestCases
		if (recurse) {
			Iterator<String> iter = getSubPkgNames(pkgName);
			while (iter.hasNext()) {
				cnt += createTestSuites(baseDir, className, iter.next(), true);
			}
		}
		return cnt;
    }
    
    /**
     * Make the directory which corresponds to the specified package.
     * @param baseDir
     * @param pkgName
     * @return package directory
     */
    private static File makeDir(File baseDir, String pkgName) {
    	File dir = new File(baseDir, pkgName.replace('.', File.separatorChar));
    	FileUtilities.mkdirs(dir);
    	return dir;
    }

	/**
	 * Command-line utilities.
	 * <p>
	 * Parameter usage:
	 * <pre>{@literal
	 *    createAllTests <baseDirPath> <className> <topPackage>
	 * }</pre>   
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			if ("createTestSuites".equals(args[0])) {
				File baseDir = new File(args[1]);
				if (!baseDir.exists() || !baseDir.isDirectory()) {
					System.err.println("TestUtilities: invalid directory (" + args[1] + ")");
					throw new RuntimeException();
				}
				String className = args[2];
				if (className.length() == 0 || !className.matches("[A-Z][a-zA-Z0-9]*?")) {
					System.err.println("TestUtilities: invalid class name (" + args[2] + ")");
					throw new RuntimeException();
				}
				String pkg = args[3];
				if (pkg.length() == 0 || !pkg.matches("[a-z][a-zA-Z0-9]*(\\.[a-z][a-zA-Z0-9]*)*")) {
					System.err.println("TestUtilities: invalid package name (" + args[3] + ")");
					throw new RuntimeException();
				}
				System.out.println("Searching for TestCases and creating TestSuites...");
				System.out.println("  package: " + pkg);
				System.out.println("  destination: " + baseDir);
				int cnt = createTestSuites(baseDir, className, pkg, true);
				System.out.println(cnt + " TestSuite(s) Created.");
			}
			System.exit(0);
		} catch (Throwable t) {
			System.err.println("TestUtilities: invalid usage");
		}
		System.exit(-1);
	}

}
