cmake_minimum_required(VERSION 2.6)

PROJECT(uv)

SET(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_C_FLAGS "-Os -fpic -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -Os  --std=c89 -pedantic -Wall -Wextra -Wno-unused-parameter  -D_GNU_SOURCE")

SET(SOURCES
      src/unix/async.c
      src/unix/core.c
      src/unix/dl.c
      src/unix/fs.c
      src/unix/getaddrinfo.c
      src/unix/linux-core.c
      src/unix/linux-inotify.c
      src/unix/linux-syscalls.c
      src/unix/loop-watcher.c
      src/unix/loop.c
      src/unix/pipe.c
      src/unix/poll.c
      src/unix/process.c
      src/unix/proctitle.c
      src/unix/signal.c
      src/unix/stream.c
      src/unix/tcp.c
      src/unix/thread.c
      src/unix/threadpool.c
      src/unix/timer.c
      src/unix/tty.c
      src/unix/udp.c
      src/fs-poll.c
      src/inet.c
      src/uv-common.c
      src/version.c
)

INCLUDE_DIRECTORIES(include src)
ADD_LIBRARY(uv SHARED ${SOURCES})
 
FILE(GLOB HEADERS "include/*.h")
 
INSTALL(TARGETS uv DESTINATION lib)
INSTALL(FILES ${HEADERS} DESTINATION include)

