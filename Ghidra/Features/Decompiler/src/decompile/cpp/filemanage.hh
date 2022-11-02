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

class FileManage {
  std::vector<std::string> pathlist;	// List of paths to search for files
  static char separator;
  static std::string buildPath(const std::vector<std::string> &pathels,int level);
  static bool testDevelopmentPath(const std::vector<std::string> &pathels,int level,std::string &root);
  static bool testInstallPath(const std::vector<std::string> &pathels,int level,std::string &root);
public:
  void addDir2Path(const std::string &path);
  void addCurrentDir(void);
  void findFile(std::string &res,const std::string &name) const; // Resolve full pathname
  void matchList(std::vector<std::string> &res,const std::string &match,bool isSuffix) const; // List of files with suffix
  static bool isDirectory(const std::string &path);
  static void matchListDir(std::vector<std::string> &res,const std::string &match,bool isSuffix,const std::string &dir,bool allowdot);
  static void directoryList(std::vector<std::string> &res,const std::string &dirname,bool allowdot=false);
  static void scanDirectoryRecursive(std::vector<std::string> &res,const std::string &matchname,const std::string &rootpath,int maxdepth);
  static void splitPath(const std::string &full,std::string &path,std::string &base);
  static bool isAbsolutePath(const std::string &full) { if (full.empty()) return false; return (full[0] == separator); }
  static std::string discoverGhidraRoot(const char *argv0);
};

#endif
