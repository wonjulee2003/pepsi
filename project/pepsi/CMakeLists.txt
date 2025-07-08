cmake_minimum_required(VERSION 3.10)

project (main VERSION 1.0)

set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake
  CACHE STRING "Vcpkg toolchain file")

find_package(SEAL)
find_package(OpenMP)

add_executable(main-base src/main-base.cpp src/server.cpp 
                         src/client.cpp src/utils.cpp)
add_executable(main2 src/main2.cpp src/server.cpp 
                         src/client.cpp src/utils.cpp)
add_executable(main-psi src/main-psi.cpp src/server.cpp 
                        src/client.cpp src/utils.cpp)
add_executable(main-psi-large src/main-psi-large.cpp src/server.cpp 
                              src/client.cpp src/utils.cpp)

add_executable(runtimeBFV src/runtimeBFV.cpp src/utils.cpp)                              

target_link_libraries(main-base SEAL::seal OpenMP::OpenMP_CXX)
target_link_libraries(main2 SEAL::seal OpenMP::OpenMP_CXX)
target_link_libraries(main-psi SEAL::seal OpenMP::OpenMP_CXX)
target_link_libraries(main-psi-large SEAL::seal OpenMP::OpenMP_CXX)

target_link_libraries(runtimeBFV SEAL::seal)

set(CMAKE_CXX_FLAGS "-g")
