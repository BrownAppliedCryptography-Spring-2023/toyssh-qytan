cmake_minimum_required(VERSION 3.10)

# project details
project(ToySSH VERSION 1.0)
set(CLIENT_EXEC_NAME toy_ssh)
set(SERVER_EXEC_NAME toy_sshd)
set(LIBRARY_NAME toy_ssh_lib)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
include(Cryptopp)

set(SOURCES
  src/pkg/ssh_client.cxx
  src/pkg/ssh_channel.cxx
  src/drivers/network_driver.cxx
  src/drivers/crypto_driver.cxx
  src/drivers/ed25519_driver.cxx
  src/util/messages.cxx
  src/util/logger.cxx
  src/util/util.cxx)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PRIVATE ${Boost_LIBRARIES})
target_link_libraries(${LIBRARY_NAME} PRIVATE cryptopp)
target_link_libraries(${LIBRARY_NAME} PRIVATE cryptopp-shared)
# target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_CRYPTO})

add_executable(${CLIENT_EXEC_NAME} src/cmd/client.cxx)
target_link_libraries(${CLIENT_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# properties
set_target_properties(
  ${LIBRARY_NAME}
      PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS YES
)

