#.rst:
# FindJavaAndSwig
# --------------
#
# Find Java and SWIG as a whole.

#if(JAVA_LIBRARIES AND JAVA_INCLUDE_DIR AND SWIG_EXECUTABLE)
if(SWIG_EXECUTABLE)
  set(JAVAANDSWIG_FOUND TRUE)
else()
  find_package(SWIG 2.0)
  if (SWIG_FOUND)
    find_package(Java 11.0)
    if(JAVA_FOUND AND SWIG_FOUND)
      mark_as_advanced(
        JAVA_LIBRARIES
        JAVA_INCLUDE_DIR
        SWIG_EXECUTABLE)
    endif()
  else()
    message(STATUS "SWIG 2 or later is required for Java support in LLDB but could not be found")
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(JavaAndSwig
                                    FOUND_VAR
                                      JAVAANDSWIG_FOUND
                                    REQUIRED_VARS
                                      JAVA_LIBRARIES
                                      JAVA_INCLUDE_DIR
                                      SWIG_EXECUTABLE)
endif()
