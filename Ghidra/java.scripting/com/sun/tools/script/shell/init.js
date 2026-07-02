/*
 * Copyright (c) 2005, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/**
 * jrunscript JavaScript built-in functions and objects.
 */

/**
 * Creates an object that delegates all method calls on
 * it to the 'invoke' method on the given delegate object.<br>
 *
 * Example:
 * <pre>
 * <code>
 *     var x  = { invoke: function(name, args) { //code...}
 *     var y = new JSInvoker(x);
 *     y.func(3, 3); // calls x.invoke('func', args); where args is array of arguments
 * </code>
 * </pre>
 * @param obj object to be wrapped by JSInvoker
 * @constructor
 */
function JSInvoker(obj) {
    return new JSAdapter({
        __get__ : function(name) {
            return function() {
                return obj.invoke(name, arguments);
            }
        }
    });
}

/**
 * This variable represents OS environment. Environment
 * variables can be accessed as fields of this object. For
 * example, env.PATH will return PATH value configured.
 */
var env = new JSAdapter({
    __get__ : function (name) {
        return java.lang.System.getenv(name);
    },
    __has__ : function (name) {
        return java.lang.System.getenv().containsKey(name);
    },
    __getIds__ : function() {
        return java.lang.System.getenv().keySet().toArray();
    },
    __delete__ : function(name) {
        println("can't delete env item");
    },
    __put__ : function (name, value) {
        println("can't change env item");
    },
    toString: function() {
        return java.lang.System.getenv().toString();
    }
});

/**
 * Creates a convenient script object to deal with java.util.Map instances.
 * The result script object's field names are keys of the Map. For example,
 * scriptObj.keyName can be used to access value associated with given key.<br>
 * Example:
 * <pre>
 * <code>
 *     var x = java.lang.SystemProperties();
 *     var y = jmap(x);
 *     println(y['java.class.path']); // prints java.class.path System property
 *     delete y['java.class.path']; // remove java.class.path System property
 * </code>
 * </pre>
 *
 * @param map java.util.Map instance that will be wrapped
 * @constructor
 */
function jmap(map) {
    return new JSAdapter({
        __get__ : function(name) {
            if (map.containsKey(name)) {
                return map.get(name);
            } else {
                return undefined;
            }
        },
        __has__ :  function(name) {
            return map.containsKey(name);
        },

        __delete__ : function (name) {
            return map.remove(name);
        },
        __put__ : function(name, value) {
            map.put(name, value);
        },
        __getIds__ : function() {
            return map.keySet().toArray();
        },
        toString: function() {
            return map.toString();
        }
    });
}

/**
 * Creates a convenient script object to deal with java.util.List instances.
 * The result script object behaves like an array. For example,
 * scriptObj[index] syntax can be used to access values in the List instance.
 * 'length' field gives size of the List. <br>
 *
 * Example:
 * <pre>
 * <code>
 *    var x = new java.util.ArrayList(4);
 *    x.add('Java');
 *    x.add('JavaScript');
 *    x.add('SQL');
 *    x.add('XML');
 *
 *    var y = jlist(x);
 *    println(y[2]); // prints third element of list
 *    println(y.length); // prints size of the list
 *
 * @param map java.util.List instance that will be wrapped
 * @constructor
 */
function jlist(list) {
    function isValid(index) {
        return typeof(index) == 'number' &&
            index > -1 && index < list.size();
    }
    return new JSAdapter({
        __get__ :  function(name) {
            if (isValid(name)) {
                return list.get(name);
            } else if (name == 'length') {
                return list.size();
            } else {
                return undefined;
            }
        },
        __has__ : function (name) {
            return isValid(name) || name == 'length';
        },
        __delete__ : function(name) {
            if (isValid(name)) {
                list.remove(name);
            }
        },
        __put__ : function(name, value) {
            if (isValid(name)) {
                list.set(name, value);
            }
        },
        __getIds__: function() {
            var res = new Array(list.size());
            for (var i = 0; i < res.length; i++) {
                res[i] = i;
            }
            return res;
        },
        toString: function() {
            return list.toString();
        }
    });
}

/**
 * This is java.lang.System properties wrapped by JSAdapter.
 * For eg. to access java.class.path property, you can use
 * the syntax sysProps["java.class.path"]
 */
var sysProps = new JSAdapter({
    __get__ : function (name) {
        return java.lang.System.getProperty(name);
    },
    __has__ : function (name) {
        return java.lang.System.getProperty(name) != null;
    },
    __getIds__ : function() {
        return java.lang.System.getProperties().keySet().toArray();
    },
    __delete__ : function(name) {
        java.lang.System.clearProperty(name);
        return true;
    },
    __put__ : function (name, value) {
        java.lang.System.setProperty(name, value);
    },
    toString: function() {
        return "<system properties>";
    }
});

// stdout, stderr & stdin
var out = java.lang.System.out;
var err = java.lang.System.err;
// can't use 'in' because it is a JavaScript keyword :-(
var inp = java.lang.System["in"];

var BufferedInputStream = java.io.BufferedInputStream;
var BufferedOutputStream = java.io.BufferedOutputStream;
var BufferedReader = java.io.BufferedReader;
var DataInputStream = java.io.DataInputStream;
var File = java.io.File;
var FileInputStream = java.io.FileInputStream;
var FileOutputStream = java.io.FileOutputStream;
var InputStream = java.io.InputStream;
var InputStreamReader = java.io.InputStreamReader;
var OutputStream = java.io.OutputStream;
var Reader = java.io.Reader;
var URL = java.net.URL;

/**
 * Generic any object to input stream mapper
 * @param str input file name, URL or InputStream
 * @return InputStream object
 * @private
 */
function inStream(str) {
    if (typeof(str) == "string") {
        // '-' means standard input
        if (str == '-') {
            return java.lang.System["in"];
        }
        // try file first
        var file = null;
        try {
            file = pathToFile(str);
        } catch (e) {
        }
        if (file && file.exists()) {
            return new FileInputStream(file);
        } else {
            try {
                // treat the string as URL
                return new URL(str).openStream();
            } catch (e) {
                throw 'file or URL ' + str + ' not found';
            }
        }
    } else {
        if (str instanceof InputStream) {
            return str;
        } else if (str instanceof URL) {
            return str.openStream();
        } else if (str instanceof File) {
            return new FileInputStream(str);
        }
    }
    // everything failed, just give input stream
    return java.lang.System["in"];
}

/**
 * Generic any object to output stream mapper
 *
 * @param out output file name or stream
 * @return OutputStream object
 * @private
 */
function outStream(out) {
    if (typeof(out) == "string") {
        if (out == '>') {
            return java.lang.System.out;
        } else {
            // treat it as file
            return new FileOutputStream(pathToFile(out));
        }
    } else {
        if (out instanceof OutputStream) {
            return out;
        } else if (out instanceof File) {
            return new FileOutputStream(out);
        }
    }

    // everything failed, just return System.out
    return java.lang.System.out;
}

/**
 * stream close takes care not to close stdin, out & err.
 * @private
 */
function streamClose(stream) {
    if (stream) {
        if (stream != java.lang.System["in"] &&
            stream != java.lang.System.out &&
            stream != java.lang.System.err) {
            try {
                stream.close();
            } catch (e) {
                println(e);
            }
        }
    }
}

/**
 * Loads and evaluates JavaScript code from a stream or file or URL<br>
 *
 * Examples:
 * <pre>
 * <code>
 *    load('test.js'); // load script file 'test.js'
 *    load('http://java.sun.com/foo.js'); // load from a URL
 * </code>
 * </pre>
 *
 * @param str input from which script is loaded and evaluated
 */
if (typeof(load) == 'undefined') {
    this.load = function(str) {
        var stream = inStream(str);
        var bstream = new BufferedInputStream(stream);
        var reader = new BufferedReader(new InputStreamReader(bstream));
        var oldFilename = engine.get(engine.FILENAME);
        engine.put(engine.FILENAME, str);
        try {
            engine.eval(reader);
        } finally {
            engine.put(engine.FILENAME, oldFilename);
            streamClose(stream);
        }
    }
}

// file system utilities

/**
 * Creates a Java byte[] of given length
 * @param len size of the array to create
 * @private
 */
function javaByteArray(len) {
    return java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, len);
}

var curDir = new File('.');

/**
 * Print present working directory
 */
function pwd() {
    println(curDir.getAbsolutePath());
}

/**
 * Changes present working directory to given directory
 * @param target directory to change to. optional, defaults to user's HOME
 */
function cd(target) {
    if (target == undefined) {
        target = sysProps["user.home"];
    }
    if (!(target instanceof File)) {
        target = pathToFile(target);
    }
    if (target.exists() && target.isDirectory()) {
        curDir = target;
    } else {
        println(target + " is not a directory");
    }
}

/**
 * Converts path to java.io.File taking care of shell present working dir
 *
 * @param pathname file path to be converted
 * @private
 */
function pathToFile(pathname) {
    var tmp = pathname;
    if (!(tmp instanceof File)) {
        tmp = new File(tmp);
    }
    if (!tmp.isAbsolute()) {
        return new File(curDir, pathname);
    } else {
        return tmp;
    }
}

/**
 * Copies a file or URL or stream to another file or stream
 *
 * @param from input file or URL or stream
 * @param to output stream or file
 */
function cp(from, to) {
    if (from == to) {
        println("file " + from + " cannot be copied onto itself!");
        return;
    }
    var inp = inStream(from);
    var out = outStream(to);
    var binp = new BufferedInputStream(inp);
    var bout = new BufferedOutputStream(out);
    var buff = javaByteArray(1024);
    var len;
    while ((len = binp.read(buff)) > 0 )
        bout.write(buff, 0, len);

    bout.flush();
    streamClose(inp);
    streamClose(out);
}

/**
 * Shows the content of a file or URL or any InputStream<br>
 * Examples:
 * <pre>
 * <code>
 *    cat('test.txt'); // show test.txt file contents
 *    cat('http://java.net'); // show the contents from the URL http://java.net
 * </code>
 * </pre>
 * @param obj input to show
 * @param pattern optional. show only the lines matching the pattern
 */
function cat(obj, pattern) {
    if (obj instanceof File && obj.isDirectory()) {
        ls(obj);
        return;
    }

    var inp = null;
    if (!(obj instanceof Reader)) {
        inp = inStream(obj);
        obj = new BufferedReader(new InputStreamReader(inp));
    }
    var line;
    if (pattern) {
        var count = 1;
        while ((line=obj.readLine()) != null) {
            if (line.match(pattern)) {
                println(count + "\t: " + line);
            }
            count++;
        }
    } else {
        while ((line=obj.readLine()) != null) {
            println(line);
        }
    }
}

/**
 * Returns directory part of a filename
 *
 * @param pathname input path name
 * @return directory part of the given file name
 */
function dirname(pathname) {
    var dirName = ".";
    // Normalize '/' to local file separator before work.
    var i = pathname.replace('/', File.separatorChar ).lastIndexOf(
        File.separator );
    if ( i != -1 )
        dirName = pathname.substring(0, i);
    return dirName;
}

/**
 * Creates a new dir of given name
 *
 * @param dir name of the new directory
 */
function mkdir(dir) {
    dir = pathToFile(dir);
    println(dir.mkdir()? "created" : "can not create dir");
}

/**
 * Creates the directory named by given pathname, including
 * any necessary but nonexistent parent directories.
 *
 * @param dir input path name
 */
function mkdirs(dir) {
    dir = pathToFile(dir);
    println(dir.mkdirs()? "created" : "can not create dirs");
}

/**
 * Removes a given file
 *
 * @param pathname name of the file
 */
function rm(pathname) {
    var file = pathToFile(pathname);
    if (!file.exists()) {
        println("file not found: " + pathname);
        return false;
    }
    // note that delete is a keyword in JavaScript!
    println(file["delete"]()? "deleted" : "can not delete");
}

/**
 * Removes a given directory
 *
 * @param pathname name of the directory
 */
function rmdir(pathname) {
    rm(pathname);
}

/**
 * Synonym for 'rm'
 */
function del(pathname) {
    rm(pathname);
}

/**
 * Moves a file to another
 *
 * @param from original name of the file
 * @param to new name for the file
 */
function mv(from, to) {
    println(pathToFile(from).renameTo(pathToFile(to))?
        "moved" : "can not move");
}

/**
 * Synonym for 'mv'.
 */
function ren(from, to) {
    mv(from, to);
}

var months = [ "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" ];

/**
 * Helper function called by ls
 * @private
 */
function printFile(f) {
    var sb = new java.lang.StringBuffer();
    sb.append(f.isDirectory()? "d" : "-");
    sb.append(f.canRead() ? "r": "-" );
    sb.append(f.canWrite() ? "w": "-" );
    sb.append(" ");

    var d = new java.util.Date(f.lastModified());
    var c = new java.util.GregorianCalendar();
    c.setTime(d);
    var day    = c.get(java.util.Calendar.DAY_OF_MONTH);
    sb.append(months[c.get(java.util.Calendar.MONTH)]
         + " " + day );
    if (day < 10) {
        sb.append(" ");
    }

    // to get fixed length 'length' field
    var fieldlen = 8;
    var len = new java.lang.StringBuffer();
    for(var j=0; j<fieldlen; j++)
        len.append(" ");
    len.insert(0, java.lang.Long.toString(f.length()));
    len.setLength(fieldlen);
    // move the spaces to the front
    var si = len.toString().indexOf(" ");
    if ( si != -1 ) {
        var pad = len.toString().substring(si);
        len.setLength(si);
        len.insert(0, pad);
    }
    sb.append(len.toString());
    sb.append(" ");
    sb.append(f.getName());
    if (f.isDirectory()) {
        sb.append('/');
    }
    println(sb.toString());
}

/**
 * Lists the files in a directory
 *
 * @param dir directory from which to list the files. optional, default to pwd
 * @param filter pattern to filter the files listed. optional, default is '.'.
 */
function ls(dir, filter) {
    if (dir) {
        dir = pathToFile(dir);
    } else {
        dir = curDir;
    }
    if (dir.isDirectory()) {
        var files = dir.listFiles();
        for (var i in files) {
            var f = files[i];
            if (filter) {
                if(!f.getName().match(filter)) {
                    continue;
                }
            }
            printFile(f);
        }
    } else {
        printFile(dir);
    }
}

/**
 * Synonym for 'ls'.
 */
function dir(d, filter) {
    ls(d, filter);
}

/**
 * Unix-like grep, but accepts JavaScript regex patterns
 *
 * @param pattern to search in files
 * @param files one or more files
 */
function grep(pattern, files /*, one or more files */) {
    if (arguments.length < 2) return;
    for (var i = 1; i < arguments.length; i++) {
        println(arguments[i] + ":");
        cat(arguments[i], pattern);
    }
}

/**
 * Find in files. Calls arbitrary callback function
 * for each matching file.<br>
 *
 * Examples:
 * <pre>
 * <code>
 *    find('.')
 *    find('.', '.*\.class', rm);  // remove all .class files
 *    find('.', '.*\.java');       // print fullpath of each .java file
 *    find('.', '.*\.java', cat);  // print all .java files
 * </code>
 * </pre>
 *
 * @param dir directory to search files
 * @param pattern to search in the files
 * @param callback function to call for matching files
 */
function find(dir, pattern, callback) {
    dir = pathToFile(dir);
    if (!callback) callback = print;
    var files = dir.listFiles();
    for (var f in files) {
        var file = files[f];
        if (file.isDirectory()) {
            find(file, pattern, callback);
        } else {
            if (pattern) {
                if (file.getName().match(pattern)) {
                    callback(file);
                }
            } else {
                callback(file);
            }
        }
    }
}

// process utilities

/**
 * Exec's a child process, waits for completion &amp; returns exit code
 *
 * @param cmd command to execute in child process
 */
function exec(cmd) {
    var process = java.lang.Runtime.getRuntime().exec(cmd);
    var inp = new DataInputStream(process.getInputStream());
    var line = null;
    while ((line = inp.readLine()) != null) {
        println(line);
    }
    process.waitFor();
    $exit = process.exitValue();
}

if (typeof(exit) == 'undefined') {
    /**
     * Exit the shell program.
     *
     * @param exitCode integer code returned to OS shell.
     * optional, defaults to 0
     */
    this.exit = function (code) {
        if (code) {
            java.lang.System.exit(code + 0);
        } else {
            java.lang.System.exit(0);
        }
    }
}

if (typeof(quit) == 'undefined') {
    /**
     * synonym for exit
     */
    this.quit = function (code) {
        exit(code);
    }
}

// XML utilities

/**
 * Converts input to DOM Document object
 *
 * @param inp file or reader. optional, without this param,
 * this function returns a new DOM Document.
 * @return returns a DOM Document object
 */
function XMLDocument(inp) {
    var factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
    var builder = factory.newDocumentBuilder();
    if (inp) {
        if (typeof(inp) == "string") {
            return builder.parse(pathToFile(inp));
        } else {
            return builder.parse(inp);
        }
    } else {
        return builder.newDocument();
    }
}

/**
 * Converts arbitrary stream, file, URL to XMLSource
 *
 * @param inp input stream or file or URL
 * @return XMLSource object
 */
function XMLSource(inp) {
    if (inp instanceof javax.xml.transform.Source) {
        return inp;
    } else if (inp instanceof Packages.org.w3c.dom.Document) {
        return new javax.xml.transform.dom.DOMSource(inp);
    } else {
        inp = new BufferedInputStream(inStream(inp));
        return new javax.xml.transform.stream.StreamSource(inp);
    }
}

/**
 * Converts arbitrary stream, file to XMLResult
 *
 * @param inp output stream or file
 * @return XMLResult object
 */
function XMLResult(out) {
    if (out instanceof javax.xml.transform.Result) {
        return out;
    } else if (out instanceof Packages.org.w3c.dom.Document) {
        return new javax.xml.transform.dom.DOMResult(out);
    } else {
        out = new BufferedOutputStream(outStream(out));
        return new javax.xml.transform.stream.StreamResult(out);
    }
}

/**
 * Perform XSLT transform
 *
 * @param inp Input XML to transform (URL, File or InputStream)
 * @param style XSL Stylesheet to be used (URL, File or InputStream). optional.
 * @param out Output XML (File or OutputStream
 */
function XSLTransform(inp, style, out) {
    switch (arguments.length) {
    case 2:
        inp = arguments[0];
        out = arguments[1];
        break;
    case 3:
        inp = arguments[0];
        style = arguments[1];
        out = arguments[2];
        break;
    default:
        println("XSL transform requires 2 or 3 arguments");
        return;
    }

    var factory = javax.xml.transform.TransformerFactory.newInstance();
    var transformer;
    if (style) {
        transformer = factory.newTransformer(XMLSource(style));
    } else {
        transformer = factory.newTransformer();
    }
    var source = XMLSource(inp);
    var result = XMLResult(out);
    transformer.transform(source, result);
    if (source.getInputStream) {
        streamClose(source.getInputStream());
    }
    if (result.getOutputStream) {
        streamClose(result.getOutputStream());
    }
}

// miscellaneous utilities

/**
 * Prints which command is selected from PATH
 *
 * @param cmd name of the command searched from PATH
 */
function which(cmd) {
    var st = new java.util.StringTokenizer(env.PATH, File.pathSeparator);
    while (st.hasMoreTokens()) {
        var file = new File(st.nextToken(), cmd);
        if (file.exists()) {
            println(file.getAbsolutePath());
            return;
        }
    }
}

/**
 * Prints IP addresses of given domain name
 *
 * @param name domain name
 */
function ip(name) {
    var addrs = InetAddress.getAllByName(name);
    for (var i in addrs) {
        println(addrs[i]);
    }
}

/**
 * Prints current date in current locale
 */
function date() {
    println(new Date().toLocaleString());
}

/**
 * Echoes the given string arguments
 */
function echo(x) {
    for (var i = 0; i < arguments.length; i++) {
        println(arguments[i]);
    }
}

if (typeof(printf) == 'undefined') {
    /**
     * This is C-like printf 
     *
     * @param format string to format the rest of the print items
     * @param args variadic argument list
     */
    this.printf = function (format, args/*, more args*/) {  
        var array = java.lang.reflect.Array.newInstance(java.lang.Object, 
                    arguments.length - 1);
        for (var i = 0; i < array.length; i++) {
            array[i] = arguments[i+1];
        }
        java.lang.System.out.printf(format, array);
    }
}

/**
 * Reads one or more lines from stdin after printing prompt
 *
 * @param prompt optional, default is '>'
 * @param multiline to tell whether to read single line or multiple lines
 */
function read(prompt, multiline) {
    if (!prompt) {
        prompt = '>';
    }
    var inp = java.lang.System["in"];
    var reader = new BufferedReader(new InputStreamReader(inp));
    if (multiline) {
        var line = '';
        while (true) {
            java.lang.System.err.print(prompt);
            java.lang.System.err.flush();
            var tmp = reader.readLine();
            if (tmp == '' || tmp == null) break;
            line += tmp + '\n';
        }
        return line;
    } else {
        java.lang.System.err.print(prompt);
        java.lang.System.err.flush();
        return reader.readLine();
    }
}

if (typeof(println) == 'undefined') {
    // just synonym to print
    this.println = print;
}

