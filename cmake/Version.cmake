
# Using autorevision.sh to generate version information

set(__SOURCE_AUTORESIVISION ${CMAKE_SOURCE_DIR}/autorevision.sh)
set(__AUTORESIVISION ${CMAKE_BINARY_DIR}/autorevision.sh)
set(__VERSION_CACHE ${CMAKE_BINARY_DIR}/version.txt)
set(__VERSION_CONFIG ${CMAKE_BINARY_DIR}/version.cmake)

file(COPY ${__SOURCE_AUTORESIVISION} DESTINATION ${CMAKE_BINARY_DIR}
	FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
	WORLD_READ WORLD_EXECUTE)

# execute autorevision.sh to generate version information
execute_process(COMMAND ${__AUTORESIVISION} -t cmake -o ${__VERSION_CACHE} 
				OUTPUT_FILE ${__VERSION_CONFIG} ERROR_QUIET)
include(${__VERSION_CONFIG})

# extract major, minor, patch version from git tag
string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" VERSION_MAJOR "${VCS_TAG}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" VERSION_MINOR "${VCS_TAG}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" VERSION_PATCH "${VCS_TAG}")
string(REGEX REPLACE "[T\\:\\+\\-]" "" VERSION_DATE "${VCS_DATE}")

if(VERSION_DAILY_BUILD)
	set(VERSION_PATCH ${VERSION_PATCH}.${VERSION_DATE})
endif()

if(NOT VERSION_MAJOR)
    set(VERSION_MAJOR 1)
endif()

if(NOT VERSION_MINOR)
    set(VERSION_MINOR 0)
endif()

if(NOT VERSION_PATCH)
    set(VERSION_PATCH 0)
endif()

set(VERSION "${VERSION_MAJOR}_${VERSION_MINOR}_${VERSION_PATCH}")
set(VERSION_BUILD "${VCS_SHORT_HASH}")

# print information
message(STATUS "Version: ${VERSION}-${VERSION_BUILD}")

option(DEFINE_GIT_VERSION "Set DEFINE_GIT_VERSION to TRUE or FALSE" TRUE)

if(DEFINE_GIT_VERSION)
	set(GIT_VERSION
			"${VERSION}-${CMAKE_BUILD_TYPE}-${VERSION_BUILD}-${VCS_BRANCH}-${VCS_TAG}-${VCS_DATE}")
	string(REGEX REPLACE "[-:+/\\.]" "_" GIT_VERSION ${GIT_VERSION})

	add_definitions(-DGIT_VERSION=${GIT_VERSION})
endif()
