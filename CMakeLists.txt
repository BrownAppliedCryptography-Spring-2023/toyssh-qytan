cmake_minimum_required(VERSION 3.10)

# project details
project(ToySSH VERSION 1.0)
set(CLIENT_EXEC_NAME toy_ssh)
set(SERVER_EXEC_NAME toy_sshd)
set(LIBRARY_NAME toy_ssh_lib)
# set(LIBRARY_NAME_CRYPTO tinyssh_lib)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
include(Sodium)

# set(SOURCES_CRYPTO
#   libtinyssh/work/blocking.c
#   libtinyssh/work/buf.c
#   libtinyssh/work/byte.c
#   libtinyssh/work/channel.c
#   libtinyssh/work/channel_drop.c
#   libtinyssh/work/channel_fork.c
#   libtinyssh/work/channel_forkpty.c
#   libtinyssh/work/channel_subsystem.c
#   libtinyssh/work/coe.c
#   libtinyssh/work/connectioninfo.c
#   libtinyssh/work/die.c
#   libtinyssh/work/dropuidgid.c
#   libtinyssh/work/e.c
#   libtinyssh/work/env.c
#   libtinyssh/work/getln.c
#   libtinyssh/work/global.c
#   libtinyssh/work/iptostr.c
#   libtinyssh/work/load.c
#   libtinyssh/work/log.c
#   libtinyssh/work/loginshell.c
#   libtinyssh/work/logsys.c
#   libtinyssh/work/main_tinysshd.c
#   libtinyssh/work/main_tinysshd_makekey.c
#   libtinyssh/work/main_tinysshd_printkey.c
#   libtinyssh/work/newenv.c
#   libtinyssh/work/numtostr.c
#   libtinyssh/work/open.c
#   libtinyssh/work/packet.c
#   libtinyssh/work/packet_auth.c
#   libtinyssh/work/packet_channel_open.c
#   libtinyssh/work/packet_channel_recv.c
#   libtinyssh/work/packet_channel_request.c
#   libtinyssh/work/packet_channel_send.c
#   libtinyssh/work/packet_get.c
#   libtinyssh/work/packet_hello.c
#   libtinyssh/work/packet_kex.c
#   libtinyssh/work/packet_kexdh.c
#   libtinyssh/work/packet_put.c
#   libtinyssh/work/packet_recv.c
#   libtinyssh/work/packet_send.c
#   libtinyssh/work/packet_unimplemented.c
#   libtinyssh/work/packetparser.c
#   libtinyssh/work/porttostr.c
#   libtinyssh/work/randommod.c
#   libtinyssh/work/readall.c
#   libtinyssh/work/savesync.c
#   libtinyssh/work/ssh.c
#   libtinyssh/work/sshcrypto.c
#   libtinyssh/work/sshcrypto_cipher.c
#   libtinyssh/work/sshcrypto_cipher_aesctr.c
#   libtinyssh/work/sshcrypto_cipher_aesctr256.c
#   libtinyssh/work/sshcrypto_cipher_chachapoly.c
#   libtinyssh/work/sshcrypto_kex.c
#   libtinyssh/work/sshcrypto_kex_curve25519.c
#   libtinyssh/work/sshcrypto_kex_nistp256.c
#   libtinyssh/work/sshcrypto_key.c
#   libtinyssh/work/sshcrypto_key_ed25519.c
#   libtinyssh/work/sshcrypto_key_nistp256ecdsa.c
#   libtinyssh/work/str.c
#   libtinyssh/work/stringparser.c
#   libtinyssh/work/subprocess_auth.c
#   libtinyssh/work/subprocess_sign.c
#   libtinyssh/work/tinysshd-makekey.c
#   libtinyssh/work/tinysshd-printkey.c
#   libtinyssh/work/tinysshd.c
#   libtinyssh/work/trymlock.c
#   libtinyssh/work/writeall.c)
# add_library(${LIBRARY_NAME_CRYPTO} ${SOURCES_CRYPTO})
# target_include_directories(${LIBRARY_NAME_CRYPTO} PUBLIC ${PROJECT_SOURCE_DIR}/libtinyssh/include)
# target_link_libraries(${LIBRARY_NAME_CRYPTO} PUBLIC ${PROJECT_SOURCE_DIR}/libtinyssh/lib/libtinynacl.a)

set(SOURCES
  src/crypto/algorithms.cxx
  src/pkg/ssh_client.cxx
  src/drivers/network_driver.cxx
  src/drivers/crypto_driver.cxx
  src/util/messages.cxx
  src/util/logger.cxx
  src/util/util.cxx)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC 
    ${PROJECT_SOURCE_DIR}/libtinyssh/include ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/libtinyssh/work)
target_link_libraries(${LIBRARY_NAME} PRIVATE ${Boost_LIBRARIES})
# target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_CRYPTO})
target_link_libraries(${LIBRARY_NAME} PRIVATE ${Sodium_LIBRARIES})

add_executable(${CLIENT_EXEC_NAME} src/cmd/client.cxx)
target_link_libraries(${CLIENT_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# properties
set_target_properties(
  ${LIBRARY_NAME}
      PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS YES
)

