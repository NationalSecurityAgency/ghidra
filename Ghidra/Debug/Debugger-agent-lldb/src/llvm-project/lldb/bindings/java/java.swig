/*
   lldb.swig

   This is the input file for SWIG, to create the appropriate C++ wrappers and
   functions for various scripting languages, to enable them to call the
   liblldb Script Bridge functions.
*/

%module lldb

%include <std_string.i>
%include "java-typemaps.swig"
%include "macros.swig"
%include "headers.swig"

%{
using namespace lldb_private;
using namespace lldb;
%}

%include "interfaces.swig"

