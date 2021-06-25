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

#ifndef __CPUI_CONSOLE_MAIN__
#define __CPUI_CONSOLE_MAIN__

#include "interface.hh"
#include <memory>

class IfcLoadFile : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcAddpath : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcSave : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcRestore : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

int console_main(int argc, const char **argv);

int32_t console_main_rust(rust::Slice<const rust::String> args);

unique_ptr<IfaceCommand> new_load_file_command();
unique_ptr<IfaceCommand> new_add_path_command();
unique_ptr<IfaceCommand> new_save_command();
unique_ptr<IfaceCommand> new_restore_command();

#endif