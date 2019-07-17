/* ###
 * IP: GHIDRA
 * NOTE: Calls to Windows APIs
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
#include "filemanage.hh"

#ifdef _WINDOWS
#include <windows.h>

#else
// POSIX functions for searching directories
extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
}
#endif

// Path name separator
#ifdef _WINDOWS
char FileManage::separator = '\\';
#else
char FileManage::separator = '/';
#endif

void FileManage::addDir2Path(const string &path)

{
  if (path.size()>0) {
    pathlist.push_back(path);
    if (path[path.size()-1] != separator)
      pathlist.back() += separator;
  }
}

void FileManage::findFile(string &res,const string &name) const

{				// Search through paths to find file with given name
  vector<string>::const_iterator iter;

  if (name[0] == separator) {
    res = name;
    ifstream s(res.c_str());
    if (s) {
      s.close();
      return;
    }
  }
  else {
    for(iter=pathlist.begin();iter!=pathlist.end();++iter) {
      res = *iter + name;
      ifstream s(res.c_str());
      if (s) {
	s.close();
	return;
      }
    }
  }
  res.clear();			// Can't find it, return empty string
}

#ifdef _WINDOWS
void FileManage::addCurrentDir(void)

{
  char dirname[256];
  
  if (0!=GetCurrentDirectoryA(256,dirname)) {
    string filename(dirname);
    addDir2Path(filename);
  }
}

#else
void FileManage::addCurrentDir(void)

{				// Add current working directory to path
  char dirname[256];
  char *buf;

  buf = getcwd(dirname,256);
  if ((char *)0 == buf) return;
  string filename(buf);
  addDir2Path(filename);
}
#endif

#ifdef _WINDOWS
bool FileManage::isDirectory(const string &path)

{
  DWORD attribs = GetFileAttributes(path.c_str());
  if (attribs == INVALID_FILE_ATTRIBUTES) return false;
  return ((attribs & FILE_ATTRIBUTE_DIRECTORY)!=0);
}

#else
bool FileManage::isDirectory(const string &path)

{
  struct stat buf;
  if (stat(path.c_str(),&buf) < 0) {
    return false;
  }
  return S_ISDIR(buf.st_mode);
}

#endif

#ifdef _WINDOWS
void FileManage::matchListDir(vector<string> &res,const string &match,bool isSuffix,const string &dirname,bool allowdot)

{
  WIN32_FIND_DATAA FindFileData;
  HANDLE hFind;
  string dirfinal;

  dirfinal = dirname;
  if (dirfinal[dirfinal.size()-1] != separator)
    dirfinal += separator;
  string regex = dirfinal + '*';

  hFind = FindFirstFileA(regex.c_str(),&FindFileData);
  if (hFind == INVALID_HANDLE_VALUE) return;
  do {
    string fullname(FindFileData.cFileName);
    if (match.size() <= fullname.size()) {
      if (allowdot||(fullname[0] != '.')) {
	if (isSuffix) {
	  if (0==fullname.compare(fullname.size()-match.size(),match.size(),match))
	    res.push_back(dirfinal + fullname);
	}
	else {
	  if (0==fullname.compare(0,match.size(),match))
	    res.push_back(dirfinal + fullname);
	}
      }
    }
  } while(0!=FindNextFileA(hFind,&FindFileData));
  FindClose(hFind);
}

#else
void FileManage::matchListDir(vector<string> &res,const string &match,bool isSuffix,const string &dirname,bool allowdot)

{				// Look through files in a directory for those matching -match-
  DIR *dir;
  struct dirent *entry;
  string dirfinal = dirname;
  if (dirfinal[dirfinal.size()-1] != separator)
    dirfinal += separator;

  dir = opendir(dirfinal.c_str());
  if (dir == (DIR *)0) return;
  entry = readdir(dir);
  while(entry != (struct dirent *)0) {
    string fullname(entry->d_name);
    if (match.size() <= fullname.size()) {
      if (allowdot||(fullname[0] != '.')) {
	if (isSuffix) {
	  if (0==fullname.compare( fullname.size()-match.size(),match.size(),match))
	    res.push_back( dirfinal + fullname );
	}
	else {
	  if (0==fullname.compare(0,match.size(),match))
	    res.push_back(dirfinal + fullname);
	}
      }
    }
    entry = readdir(dir);
  }
  closedir(dir);
}
#endif

void FileManage::matchList(vector<string> &res,const string &match,bool isSuffix) const

{
  vector<string>::const_iterator iter;

  for(iter=pathlist.begin();iter!=pathlist.end();++iter)
    matchListDir(res,match,isSuffix,*iter,false);
}

#ifdef _WINDOWS

void FileManage::directoryList(vector<string> &res,const string &dirname,bool allowdot)

{
  WIN32_FIND_DATAA FindFileData;
  HANDLE hFind;
  string dirfinal = dirname;
  if (dirfinal[dirfinal.size()-1] != separator)
    dirfinal += separator;
  string regex = dirfinal + "*";
  const char *s = regex.c_str();
  

  hFind = FindFirstFileA(s,&FindFileData);
  if (hFind == INVALID_HANDLE_VALUE) return;
  do {
    if ( (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY ) {
      string fullname(FindFileData.cFileName);
      if (allowdot || (fullname[0] != '.'))
	res.push_back(dirfinal + fullname);
    }
  } while(0!=FindNextFileA(hFind,&FindFileData));
  FindClose(hFind);
}

#else
void FileManage::directoryList(vector<string> &res,const string &dirname,bool allowdot)

{ // List full pathnames of all directories under the directory -dir-
  DIR *dir;
  struct dirent *entry;
  string dirfinal;

  dirfinal = dirname;
  if (dirfinal[dirfinal.size()-1] != separator)
    dirfinal += separator;

  dir = opendir(dirfinal.c_str());
  if (dir == (DIR *)0) return;
  entry = readdir(dir);
  while(entry != (struct dirent *)0) {
    if (entry->d_type == DT_DIR) {
      string fullname(entry->d_name);
      if ((fullname!=".")&&(fullname!="..")) {
	if (allowdot || (fullname[0] != '.'))
	  res.push_back( dirfinal + fullname );
      }
    }
    entry = readdir(dir);
  }
  closedir(dir);
}

#endif

void FileManage::scanDirectoryRecursive(vector<string> &res,const string &matchname,const string &rootpath,int maxdepth)

{
  if (maxdepth == 0) return;
  vector<string> subdir;
  directoryList(subdir,rootpath);
  vector<string>::const_iterator iter;
  for(iter = subdir.begin();iter!=subdir.end();++iter) {
    const string &curpath( *iter );
    string::size_type pos = curpath.rfind(separator);
    if (pos == string::npos)
      pos = 0;
    else
      pos = pos + 1;
    if (curpath.compare(pos,string::npos,matchname)==0)
      res.push_back(curpath);
    else
      scanDirectoryRecursive(res,matchname,curpath,maxdepth-1); // Recurse
  }
}

void FileManage::splitPath(const string &full,string &path,string &base)

{ // Split path string -full- into its -base-name and -path- (relative or absolute)
  // If there is no path, i.e. only a basename in full, then -path- will return as an empty string
  // otherwise -path- will be non-empty and end in a separator character
  string::size_type end = full.size()-1;
  if (full[full.size()-1] == separator) // Take into account terminating separator
    end = full.size()-2;
  string::size_type pos = full.rfind(separator,end);
  if (pos == string::npos) {	// Didn't find any separator
    base = full;
    path.clear();
  }
  else {
    string::size_type sz = (end - pos);
    base = full.substr(pos+1,sz);
    path = full.substr(0,pos+1);
  }
}

string FileManage::buildPath(const vector<string> &pathels,int level)

{ // Build an absolute path using elements from -pathels-, in reverse order
  // Build up to and including pathels[level]
  ostringstream s;

  for(int i=pathels.size()-1;i>=level;--i) {
    s << separator;
    s << pathels[i];
  }
  return s.str();
}

bool FileManage::testDevelopmentPath(const vector<string> &pathels,int level,string &root)

{ // Given pathels[level] is "Ghidra", determine if this is a Ghidra development layout
  if (level + 2 >= pathels.size()) return false;
  string parent = pathels[level + 1];
  if (parent.size() < 11) return false;
  string piecestr = parent.substr(0,7);
  if (piecestr != "ghidra.") return false;
  piecestr = parent.substr(parent.size() - 4);
  if (piecestr != ".git") return false;
  root = buildPath(pathels,level+2);
  vector<string> testpaths1;
  vector<string> testpaths2;
  scanDirectoryRecursive(testpaths1,"ghidra.git",root,1);
  if (testpaths1.size() != 1) return false;
  scanDirectoryRecursive(testpaths2,"Ghidra",testpaths1[0],1);
  return (testpaths2.size() == 1);
}

bool FileManage::testInstallPath(const vector<string> &pathels,int level,string &root)

{
  if (level + 1 >= pathels.size()) return false;
  root = buildPath(pathels,level+1);
  vector<string> testpaths1;
  vector<string> testpaths2;
  scanDirectoryRecursive(testpaths1,"server",root,1);
  if (testpaths1.size() != 1) return false;
  scanDirectoryRecursive(testpaths2,"server.conf",testpaths1[0],1);
  return (testpaths2.size() == 1);
}

string FileManage::discoverGhidraRoot(const char *argv0)

{ // Find the root of the ghidra distribution based on current working directory and passed in path
  vector<string> pathels;
  string cur(argv0);
  string base;
  int skiplevel = 0;
  bool isAbs = isAbsolutePath(cur);

  for(;;) {
    int sizebefore = cur.size();
    splitPath(cur,cur,base);
    if (cur.size() == sizebefore) break;
    if (base == ".")
      skiplevel += 1;
    else if (base == "..")
      skiplevel += 2;
    if (skiplevel > 0)
      skiplevel -= 1;
    else
      pathels.push_back(base);
  }
  if (!isAbs) {
    FileManage curdir;
    curdir.addCurrentDir();
    cur = curdir.pathlist[0];
    for(;;) {
      int sizebefore = cur.size();
      splitPath(cur,cur,base);
      if (cur.size() == sizebefore) break;
      pathels.push_back(base);
    }
  }

  for(int i=0;i<pathels.size();++i) {
    if (pathels[i] != "Ghidra") continue;
    string root;
    if (testDevelopmentPath(pathels,i,root))
      return root;
    if (testInstallPath(pathels,i,root))
      return root;
  }
  return "";
}
