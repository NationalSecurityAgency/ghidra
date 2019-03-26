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
// Generic (POSIX) class for searching files and managing paths

#ifndef __FILEMANAGE__
#define __FILEMANAGE__

#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>

using namespace std;

class FileManage {
  vector<string> pathlist;	// List of paths to search for files
  static char separator;
  static string buildPath(const vector<string> &pathels,int level);
  static bool testDevelopmentPath(const vector<string> &pathels,int level,string &root);
  static bool testInstallPath(const vector<string> &pathels,int level,string &root);
public:
  void addDir2Path(const string &path);
  void addCurrentDir(void);
  void findFile(string &res,const string &name) const; // Resolve full pathname
  void matchList(vector<string> &res,const string &match,bool isSuffix) const; // List of files with suffix
  static bool isDirectory(const string &path);
  static void matchListDir(vector<string> &res,const string &match,bool isSuffix,const string &dir,bool allowdot);
  static void directoryList(vector<string> &res,const string &dirname,bool allowdot=false);
  static void scanDirectoryRecursive(vector<string> &res,const string &matchname,const string &rootpath,int maxdepth);
  static void splitPath(const string &full,string &path,string &base);
  static bool isAbsolutePath(const string &full) { if (full.empty()) return false; return (full[0] == separator); }
  static string discoverGhidraRoot(const char *argv0);
};

#endif
