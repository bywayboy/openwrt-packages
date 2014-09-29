cmake_minimum_required(VERSION 2.6)

PROJECT(hellorust)

SET(CMAKE_SYSTEM_NAME Linux)

SET(CMAKE_C_FLAGS "-Wall -Os -std=gnu99 -pthread -fpic -D_GNU_SOURCE")


SET(SOURCES 
	hellorust.rs
)

INSTALL(TARGETS hellorust
	RUNTIME DESTINATION /usr/sbin
)
